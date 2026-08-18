const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const { Redis } = require("@upstash/redis");
const rateLimit = require("express-rate-limit");
const app = express();


// ==========================================
// 1. CẤU HÌNH BẢO MẬT (CORS & RATE LIMIT)
// ==========================================

// Khóa CORS
const ALLOWED_ORIGINS = new Set([
    "https://web.telegram.org",
    "https://t.me",
    "https://my-telegram-game-jet.vercel.app"
]);

app.use(cors({
    origin(origin, callback) {

        // Requests không có Origin
        // ví dụ server-to-server
        if (!origin) {
            return callback(null, true);
        }

        if (ALLOWED_ORIGINS.has(origin)) {
            return callback(null, true);
        }

        return callback(
            new Error("CORS Policy: Origin không được phép")
        );
    },

    methods: ["GET", "POST", "OPTIONS"],

    allowedHeaders: [
        "Content-Type",
        "Authorization"
    ]
}));
app.use(express.json());

// Chống Spam API (Rate Limiting) - Chỉ áp dụng cho các route /api/
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 phút
    max: 45, // Tối đa 36 request/phút cho 1 IP
    message: { ok: false, error: "Bạn gửi quá nhiều yêu cầu, hãy thử lại sau ít phút!" }
});

app.use("/api/", apiLimiter);

// ==========================================
// 2. KHỞI TẠO DỊCH VỤ (SUPABASE & REDIS)
// ==========================================
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// ==========================================
// 3. CÁC HÀM TIỆN ÍCH (UTILS)
// ==========================================
function verifyTelegramInitData(initData, botToken) {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) return null;
    params.delete("hash");

    const authDate = params.get("auth_date");
    if (!authDate) return null;

    const currentTime = Math.floor(Date.now() / 1000);
    if (currentTime - parseInt(authDate, 10) > 7200) return null; // Quá 2 tiếng

    const dataCheckString = [...params.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `${key}=${value}`)
        .join("\n");

    const secretKey = crypto.createHmac("sha256", "WebAppData").update(botToken).digest();
    const calculatedHash = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

    if (calculatedHash !== hash) return null;
    return JSON.parse(params.get("user"));
}

async function getCachedRpc(cacheKey, rpcName, rpcParams = {}, ttlSeconds = 30) {
    try {
        const cachedData = await redis.get(cacheKey);
        if (cachedData !== null && cachedData !== undefined) {
            return { data: cachedData, source: "redis" };
        }
        const { data, error } = await supabase.rpc(rpcName, rpcParams);
        if (error) throw error;
        if (data) await redis.set(cacheKey, data, { ex: ttlSeconds });
        return { data, source: "supabase" };
    } catch (err) {
        console.error(`[Cache Error] ${cacheKey}:`, err.message);
        const { data } = await supabase.rpc(rpcName, rpcParams);
        return { data, source: "fallback" };
    }
}

// ==========================================
// REDIS RATE LIMIT - TELEGRAM ID + ACTION
// ==========================================

const RATE_LIMITS = {
    // Read-only
    getTopBar:        { limit: 20, window: 10 },
    getActivePet:     { limit: 20, window: 10 },
    getMyPets:        { limit: 15, window: 10 },
    getBattlePage:    { limit: 15, window: 10 },
    getBattleHistory: { limit: 10, window: 10 },
    getWithdrawPage:  { limit: 10, window: 10 },
    getReferralPage:  { limit: 10, window: 10 },

    // Gameplay
    startGame:        { limit: 3, window: 30 },
    findOpponent:     { limit: 5, window: 10 },
    battle:           { limit: 5, window: 10 },

    // Pet / resources
    feedPet:          { limit: 5, window: 10 },
    upgradePetStat:   { limit: 5, window: 10 },
    switchPet:        { limit: 5, window: 10 },

    // Summon
    summonOne:        { limit: 3, window: 10 },
    summonFive:       { limit: 2, window: 10 },

    // Daily / tasks
    dailyCheckin:     { limit: 3, window: 30 },

    // Economy
    exchangePoints:   { limit: 3, window: 30 },

    // High-risk
    redeemGiftCode:   { limit: 3, window: 60 },
    withdrawCreate:   { limit: 2, window: 60 },
    claimReferralReward: { limit: 3, window: 60 },

    // Sunmoon
    sunMoonJoin:       { limit: 3, window: 10 },
    sunMoonSelectCell: { limit: 5, window: 10 },
    sunMoonLeaveQueue: { limit: 3, window: 10 },
    sunMoonResult:     { limit: 5, window: 10 },
    sunMoonState:      { limit: 10, window: 10 },
    telegramTask:      {  limit: 3, window: 60 },
    batchData:         { limit: 10, window: 10 }
};


// Trả về:
// {
//   allowed: true/false,
//   remaining: number,
//   retryAfter: seconds
// }
async function checkTelegramRateLimit(
    telegramId,
    action
) {
    const config = RATE_LIMITS[action];

    // Action không nằm trong danh sách
    // → không áp rate-limit riêng
    if (!config) {
        return {
            allowed: true,
            remaining: null,
            retryAfter: 0
        };
    }

    const key =
        `rl:v1:${telegramId}:${action}`;

    try {
        // Tạo counter + TTL trong lần request đầu tiên
        const created = await redis.set(
            key,
            "1",
            {
                nx: true,
                ex: config.window
            }
        );

        if (created) {
            return {
                allowed: true,
                remaining: config.limit - 1,
                retryAfter: 0
            };
        }

        // Key đã tồn tại → tăng counter
        const count = await redis.incr(key);

        if (count > config.limit) {
            const ttl = await redis.ttl(key);

            return {
                allowed: false,
                remaining: 0,
                retryAfter:
                    ttl > 0
                        ? ttl
                        : config.window
            };
        }

        return {
            allowed: true,
            remaining: config.limit - count,
            retryAfter: 0
        };

    } catch (err) {
        /*
         * Redis lỗi không được làm game chết.
         *
         * Supabase/Postgres vẫn là lớp bảo vệ cuối.
         */
        console.error(
            `[Redis RateLimit Error] ${action}:`,
            err.message
        );

        return {
            allowed: true,
            remaining: null,
            retryAfter: 0
        };
    }
}

// ==========================================
// 4. DANH SÁCH CONFIG RPC
// ==========================================
const USER_RPC_MAP = {
    upgradePetStat: "rpc_upgrade_pet_stat", feedPet: "rpc_feed_pet",
    missionPage: "rpc_get_mission_page", battle: "rpc_battle", dailyCheckin: "rpc_daily_checkin",
    startGame: "rpc_start_game", redeemGiftCode: "redeem_gift_code", claimReferralReward: "rpc_claim_referral_reward",
    summonOne: "rpc_summon_one", summonFive: "rpc_summon_five", exchangePoints: "exchange_points",
    withdrawCreate: "rpc_withdraw_create", switchPet: "rpc_switch_pet", findOpponent: "rpc_find_opponent",
    getTopBar: "rpc_get_topbar",
    getActivePet: "rpc_get_active_pet_page",
    getMyPets: "rpc_get_my_pets",
    getBattlePage: "rpc_get_battle_page",
    getBattleHistory: "rpc_get_battle_history",
    getWithdrawPage: "rpc_get_withdraw_page",
    getReferralPage: "rpc_get_referral_page",
    WatchPet: "rpc_get_active_pet",
    sunMoonJoin: "rpc_sunmoon_join",
    sunMoonState: "rpc_sunmoon_state",
    sunMoonSelectCell: "rpc_sunmoon_select_cell",
    sunMoonLeaveQueue: "rpc_sunmoon_leave_queue",
    sunMoonResult: "rpc_sunmoon_result"
};

const ADMIN_RPC_MAP = {
    createGiftCode: "rpc_admin_create_giftcode", rejectWithdraw: "rpc_admin_reject_withdraw",
    approveWithdraw: "rpc_admin_approve_withdraw", getWithdraws: "rpc_admin_get_withdraws",
    toggleMaintenance: "rpc_admin_toggle_maintenance"
};

const RPC_CONFIG = {
    "rpc_get_active_pet": { ttl: 8, isUserSpecific: true }, "rpc_get_active_pet_page": { ttl: 20, isUserSpecific: true },
    "rpc_get_my_pets": { ttl: 30, isUserSpecific: true }, "rpc_get_topbar": { ttl: 10, isUserSpecific: true },
    "rpc_get_battle_page": { ttl: 20, isUserSpecific: true }, "rpc_get_battle_history": { ttl: 20, isUserSpecific: true },
    "rpc_get_withdraw_page": { ttl: 20, isUserSpecific: true }, "rpc_get_withdraw_history": { ttl: 60, isUserSpecific: true },
    "rpc_get_referral_page": { ttl: 15, isUserSpecific: true }, "rpc_get_battle_leaderboard": { ttl: 1800, isUserSpecific: false },
    "rpc_get_coin_leaderboard": { ttl: 1800, isUserSpecific: false }, "rpc_get_referral_leaderboard": { ttl: 1800, isUserSpecific: false },
    "rpc_get_leaderboard_season": { ttl: 3600, isUserSpecific: false }
};
// ==========================================
// BATCH RPC ALLOWLIST
// CHỈ READ-ONLY RPC ĐƯỢC PHÉP ĐI QUA BATCH
// ==========================================
const BATCH_RPC_ALLOWLIST = new Set([
    "rpc_get_topbar",
    "rpc_get_active_pet",
]);
// ==========================================
// 5. ĐỊNH TUYẾN CÁC API (ROUTES)
// ==========================================

// Ping
app.get("/ping", (req, res) => res.status(200).send("OK"));

// API: Login
app.post("/api/login", async (req, res) => {
    const { initData } = req.body;
    if (!initData) return res.status(400).json({ error: "Missing initData" });
    const user = verifyTelegramInitData(initData, process.env.BOT_TOKEN);
    if (!user) return res.status(401).json({ error: "Invalid initData" });

    const { data: banned } = await supabase.from("banned_users").select("telegram_id").eq("telegram_id", user.id).maybeSingle();
    if (banned) return res.status(403).json({ error: "BANNED" });

    const token = jwt.sign({ telegram_id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "30m" });
    return res.json({ ok: true, token, telegram_id: user.id, username: user.username, first_name: user.first_name });
});

// API: User RPC
app.post("/api/userRpc", async (req, res) => {
    const { token, action, params = {} } = req.body;

    if (!token) {
        return res.status(401).json({
            error: "Missing token"
        });
    }

    try {
        const payload = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        const telegramId =
            Number(payload.telegram_id);

        if (
            !Number.isSafeInteger(telegramId) ||
            telegramId <= 0
        ) {
            return res.status(401).json({
                error: "INVALID_TOKEN"
            });
        }

        const rpc = USER_RPC_MAP[action];

        if (!rpc) {
            return res.status(400).json({
                error: "Unknown action"
            });
        }

        // ==========================================
        // REDIS RATE LIMIT
        // ==========================================

        const rate = await checkTelegramRateLimit(
            telegramId,
            action
        );

        if (!rate.allowed) {
            return res.status(429).json({
                ok: false,
                error: "RATE_LIMITED",
                retry_after: rate.retryAfter
            });
        }

        // ==========================================
        // KHÔNG CHO CLIENT GIẢ TELEGRAM ID
        // ==========================================

        params.p_telegram_id = telegramId;

        const {
            data,
            error
        } = await supabase.rpc(
            rpc,
            params
        );

        if (error) {
            return res.status(500).json({
                ok: false,
                error: error.message
            });
        }

        return res.json({
            ok: true,
            data
        });

    } catch (err) {

        if (
            err.name === "JsonWebTokenError" ||
            err.name === "TokenExpiredError"
        ) {
            return res.status(401).json({
                error: "INVALID_TOKEN"
            });
        }

        console.error(
            "[userRpc]",
            err
        );

        return res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

// API: Admin RPC
app.post("/api/adminRpc", async (req, res) => {
    const { token, action, params = {} } = req.body;
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const rpc = ADMIN_RPC_MAP[action];
        if (!rpc) return res.status(400).json({ error: "Unknown action" });
        
        const adminId = payload.telegram_id;
        const { data: admin, error: adminError } = await supabase.from("admins").select("telegram_id").eq("telegram_id", adminId).maybeSingle();
        if (adminError) return res.status(500).json({ error: adminError.message });
        if (!admin) return res.status(403).json({ error: "NOT_ADMIN" });
        
        params.p_admin_id = adminId;
        const { data, error } = await supabase.rpc(rpc, params);
        if (error) return res.status(500).json({ error: error.message });
        return res.json({ ok: true, data });
    } catch (err) {
        return res.status(401).json({ error: "INVALID_TOKEN" });
    }
});

const TELEGRAM_TASK_CHATS = {
    1: "-1003870922007",
    2: "-1004469756258"
};

app.post("/api/claimTelegramTask", async (req, res) => {
    const { token, taskId } = req.body;

    if (!token) {
        return res.status(401).json({
            ok: false,
            error: "MISSING_TOKEN"
        });
    }

    if (![1, 2].includes(Number(taskId))) {
        return res.status(400).json({
            ok: false,
            error: "INVALID_TASK"
        });
    }

    try {
        const payload = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        const telegramId = Number(payload.telegram_id);
        const rate = await checkTelegramRateLimit(
             telegramId,
             "telegramTask"
        );

        if (!rate.allowed) {
           return res.status(429).json({
               ok: false,
               error: "RATE_LIMITED",
               retry_after: rate.retryAfter
           });
        }
        const chatId = TELEGRAM_TASK_CHATS[Number(taskId)];

        const url =
            `https://api.telegram.org/bot${process.env.BOT_TOKEN}` +
            `/getChatMember?chat_id=${encodeURIComponent(chatId)}` +
            `&user_id=${telegramId}`;

        const response = await fetch(url);
        const result = await response.json();

        if (!result.ok) {
            return res.status(400).json({
                ok: false,
                error: "TELEGRAM_CHECK_FAILED"
            });
        }

        const status = result.result?.status;

        const joined =
            status === "member" ||
            status === "administrator" ||
            status === "creator";

        if (!joined) {
            return res.status(403).json({
                ok: false,
                error: "NOT_JOINED"
            });
        }

        const { data, error } = await supabase.rpc(
            "rpc_claim_telegram_task",
            {
                p_telegram_id: telegramId,
                p_task_id: Number(taskId)
            }
        );

        if (error) {
            console.error("[claimTelegramTask]", error);

            return res.status(500).json({
                ok: false,
                error: "CLAIM_FAILED"
            });
        }

        return res.json({
            ok: true,
            data
        });

    } catch (err) {

        if (
            err.name === "JsonWebTokenError" ||
            err.name === "TokenExpiredError"
        ) {
            return res.status(401).json({
                ok: false,
                error: "INVALID_TOKEN"
            });
        }

        console.error("[claimTelegramTask]", err);

        return res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

// API: Get Data (Cache)
app.post("/api/getData", async (req, res) => {
    const { rpcName, params = {}, token } = req.body;
    if (!rpcName || !RPC_CONFIG[rpcName]) return res.status(400).json({ error: "RPC không hợp lệ" });
    const config = RPC_CONFIG[rpcName];
    let finalTelegramId = null;

    if (config.isUserSpecific) {
        if (!token) return res.status(401).json({ error: "Missing token" });
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET);
            finalTelegramId = payload.telegram_id;
            params.p_telegram_id = finalTelegramId;
        } catch (err) {
            return res.status(401).json({ error: "INVALID_TOKEN" });
        }
    }
    const cacheKey = config.isUserSpecific ? `${rpcName}:user_${finalTelegramId}` : `${rpcName}:global`;
    try {
        const result = await getCachedRpc(cacheKey, rpcName, params, config.ttl);
        return res.json({ ok: true, source: result.source, data: result.data });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// ==========================================
// API: Batch Data - READ ONLY
// ==========================================
app.post("/api/batchData", async (req, res) => {
    const { requests, token } = req.body;

    if (!Array.isArray(requests)) {
        return res.status(400).json({
            ok: false,
            error: "INVALID_REQUESTS"
        });
    }

    // Giới hạn số RPC trong một batch
    if (requests.length < 1 || requests.length > 5) {
        return res.status(400).json({
            ok: false,
            error: "INVALID_BATCH_SIZE"
        });
    }

    if (!token) {
        return res.status(401).json({
            ok: false,
            error: "MISSING_TOKEN"
        });
    }

    try {
        const payload = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        if (!payload.telegram_id) {
            return res.status(401).json({
                ok: false,
                error: "INVALID_TOKEN"
            });
        }

        const results = await Promise.all(
            requests.map(async (item) => {

                const rpcName = item?.rpcName;

                // Tuyệt đối không cho client tự chọn RPC
                if (!BATCH_RPC_ALLOWLIST.has(rpcName)) {
                    throw new Error("RPC_NOT_ALLOWED");
                }

                const params = {
                    ...(item?.params || {}),
                    p_telegram_id: payload.telegram_id
                };

                const config = RPC_CONFIG[rpcName];

                // Bắt buộc phải là RPC user-specific
                if (!config || !config.isUserSpecific) {
                    throw new Error("RPC_NOT_ALLOWED");
                }

                const cacheKey =
                    `${rpcName}:user_${payload.telegram_id}`;

                const result = await getCachedRpc(
                    cacheKey,
                    rpcName,
                    params,
                    config.ttl
                );

                return {
                    rpcName,
                    data: result.data
                };
            })
        );

        return res.json({
            ok: true,
            data: results
        });

    } catch (err) {

        if (err.message === "RPC_NOT_ALLOWED") {
            return res.status(403).json({
                ok: false,
                error: "RPC_NOT_ALLOWED"
            });
        }

        if (
            err.name === "JsonWebTokenError" ||
            err.name === "TokenExpiredError"
        ) {
            return res.status(401).json({
                ok: false,
                error: "INVALID_TOKEN"
            });
        }

        console.error("[batchData]", err);

        return res.status(500).json({
            ok: false,
            error: "BATCH_FAILED"
        });
    }
});

// API: App Status
app.post("/api/appStatus", async (req, res) => {
    const { token } = req.body;
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const [{ data: system, error: systemError }, { data: admin, error: adminError }] = await Promise.all([
            supabase.from("system_settings").select("maintenance").eq("id", 1).single(),
            supabase.from("admins").select("telegram_id").eq("telegram_id", payload.telegram_id).maybeSingle()
        ]);
        if (systemError || adminError) return res.status(500).json({ error: "Database error" });
        return res.json({ ok: true, maintenance: system.maintenance, isAdmin: !!admin });
    } catch (err) {
        return res.status(401).json({ error: "INVALID_TOKEN" });
    }
});

// API: Check Telegram Task
app.post("/api/checkTelegramTask", async (req, res) => {
    const { initData, chatId } = req.body;
    const user = verifyTelegramInitData(initData, process.env.BOT_TOKEN);
    if (!user) return res.status(401).json({ error: "Invalid initData" });
    const url = `https://api.telegram.org/bot${process.env.BOT_TOKEN}/getChatMember?chat_id=${chatId}&user_id=${user.id}`;
    const response = await fetch(url);
    const result = await response.json();
    if (!result.ok) return res.json({ joined: false, telegram: result });
    const status = result.result.status;
    return res.json({ joined: status === "member" || status === "administrator" || status === "creator", status });
});        
// ==========================================
// MONETAG POSTBACK
// SERVER-TO-SERVER REWARD
// ==========================================

app.get("/api/monetag-postback", async (req, res) => {
    try {

        const {
            telegram_id,
            ymid,
            task_type,
            price,
            zone,
            event,
            reward,
            key
        } = req.query;


        // ==========================================
        // 1. KIỂM TRA SECRET
        // ==========================================

        const expectedSecret =
            process.env.MONETAG_POSTBACK_SECRET;

        if (!expectedSecret) {
            console.error(
                "[Monetag] MONETAG_POSTBACK_SECRET chưa được cấu hình"
            );

            return res.status(500).send("Server configuration error");
        }
        
        if (
            typeof key !== "string" ||
            key !== expectedSecret
        ) {
            console.warn(
                "[Monetag] Invalid secret"
            );

            return res.status(401).send("Unauthorized");
        }


        // ==========================================
        // 2. KIỂM TRA TELEGRAM ID
        // ==========================================

        if (!telegram_id) {
            console.warn(
                "[Monetag] Missing telegram_id"
            );

            return res.status(400).send("Missing telegram_id");
        }

        const telegramId = Number(telegram_id);

        if (
            !Number.isSafeInteger(telegramId) ||
            telegramId <= 0
        ) {
            console.warn(
                "[Monetag] Invalid telegram_id:",
                telegram_id
            );

            return res.status(400).send("Invalid telegram_id");
        }


        // ==========================================
        // 3. KIỂM TRA YMID
        // ==========================================

        if (
            typeof ymid !== "string" ||
            !ymid.trim()
        ) {
            console.warn(
                "[Monetag] Missing ymid"
            );

            return res.status(400).send("Missing ymid");
        }

        const ymidValue = ymid.trim();


        // ==========================================
        // 4. CHỈ CHO PHÉP 4 LOẠI REWARD
        // ==========================================

        const allowedTasks = new Set([
            "food",
            "power",
            "battle",
            "coin",
            "sunmoon"
        ]);

        const taskType = String(task_type || "").trim();

        if (!allowedTasks.has(taskType)) {

            console.warn(
                `[Monetag] Invalid task_type: ${taskType}`
            );

            return res.status(400).send("Invalid task_type");
        }


        // ==========================================
        // 5. KHÓA MAIN ZONE
        // ==========================================

        const EXPECTED_ZONE_ID = "11154093";

        const zoneId = String(zone || "").trim();

        if (zoneId !== EXPECTED_ZONE_ID) {

            console.warn(
                `[Monetag] Invalid zone | ` +
                `received=${zoneId} | ` +
                `expected=${EXPECTED_ZONE_ID}`
            );

            return res.status(403).send("Invalid zone");
        }


        // ==========================================
        // 6. KIỂM TRA EVENT
        // Monetag hiện hỗ trợ:
        // impression / click
        // ==========================================

        const eventType = String(event || "").trim();

        if (
            eventType !== "impression" &&
            eventType !== "click"
        ) {

            console.warn(
                `[Monetag] Invalid event: ${eventType}`
            );

            return res.status(400).send("Invalid event");
        }


        // ==========================================
        // 7. CHỈ CỘNG THƯỞNG CHO VALUED
        // ==========================================

        const rewardType = String(reward || "").trim();

        if (rewardType !== "valued") {

            console.log(
                `[Monetag] Non-valued event | ` +
                `ID=${telegramId} | ` +
                `Task=${taskType} | ` +
                `Reward=${rewardType} | ` +
                `ymid=${ymidValue}`
            );

            // Không cộng thưởng.
            // Trả 200 để Monetag không retry.
            return res.status(200).send("IGNORED");
        }


        // ==========================================
        // 8. KIỂM TRA PRICE
        // ==========================================

        const estimatedPrice =
            Number.parseFloat(price || "0");

        if (
            !Number.isFinite(estimatedPrice) ||
            estimatedPrice < 0
        ) {

            console.warn(
                "[Monetag] Invalid price:",
                price
            );

            return res.status(400).send("Invalid price");
        }


        // ==========================================
// 9. XỬ LÝ REWARD ATOMIC
// ==========================================

const {
    data: processResult,
    error: processError
} = await supabase.rpc(
    "rpc_process_monetag_reward",
    {
        p_telegram_id: telegramId,
        p_ymid: ymidValue,
        p_task_type: taskType,
        p_event_type: eventType,
        p_reward_event_type: rewardType,
        p_price: estimatedPrice,
        p_zone_id: zoneId
    }
);

if (processError) {
    console.error(
        "[Monetag] Atomic reward error:",
        processError.message
    );

    return res.status(500).send("Reward error");
}

const processStatus =
    processResult?.status;

if (processStatus === "DUPLICATE") {
    console.log(
        `[Monetag] Duplicate ignored | ymid=${ymidValue}`
    );

    return res.status(200).send("DUPLICATE");
}

if (processStatus === "IGNORED") {
    console.log(
        `[Monetag] Ignored | ymid=${ymidValue}`
    );

    return res.status(200).send("IGNORED");
}

if (processStatus !== "SUCCESS") {
    console.warn(
        `[Monetag] Reward not granted | ` +
        `status=${processStatus} | ` +
        `ID=${telegramId} | ` +
        `Task=${taskType} | ` +
        `ymid=${ymidValue}`
    );

    return res.status(200).send("IGNORED");
}

// ==========================================
// SUCCESS
// ==========================================

console.log(
    `[Monetag SUCCESS] ` +
    `ID=${telegramId} | ` +
    `Task=${taskType} | ` +
    `Event=${eventType} | ` +
    `Reward=${rewardType} | ` +
    `Price=$${estimatedPrice} | ` +
    `Zone=${zoneId} | ` +
    `ymid=${ymidValue}`
);

return res.status(200).send("OK");

    } catch (err) {

        console.error(
            "[Monetag Postback Fatal Error]:",
            err
        );

        return res.status(500).send("Server error");
    }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server chạy mượt mà tại cổng ${PORT}`));
        
