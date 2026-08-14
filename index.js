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
const allowedOrigins = [
    "https://my-game-backend-o7ij.onrender.com",
    "https://web.telegram.org",
    "https://t.me",
    "https://my-telegram-game-jet.vercel.app"
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.some(domain => origin.startsWith(domain))) {
            callback(null, true);
        } else {
            callback(new Error("CORS Policy: Không có quyền truy cập!"));
        }
    }
}));

app.use(express.json());

// Chống Spam API (Rate Limiting) - Chỉ áp dụng cho các route /api/
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 phút
    max: 25, // Tối đa 25 request/phút cho 1 IP
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
// 4. DANH SÁCH CONFIG RPC
// ==========================================
const USER_RPC_MAP = {
    claimAd: "rpc_claim_ad_task", upgradePetStat: "rpc_upgrade_pet_stat", feedPet: "rpc_feed_pet",
    missionPage: "rpc_get_mission_page", battle: "rpc_battle", dailyCheckin: "rpc_daily_checkin",
    startGame: "rpc_start_game", redeemGiftCode: "redeem_gift_code", claimReferralReward: "rpc_claim_referral_reward",
    summonOne: "rpc_summon_one", summonFive: "rpc_summon_five", exchangePoints: "exchange_points",
    withdrawCreate: "rpc_withdraw_create", switchPet: "rpc_switch_pet", findOpponent: "rpc_find_opponent",
    claimTelegramTask: "rpc_claim_telegram_task",
    getTopBar: "rpc_get_topbar",
    getActivePet: "rpc_get_active_pet_page",
    getMyPets: "rpc_get_my_pets",
    getBattlePage: "rpc_get_battle_page",
    getBattleHistory: "rpc_get_battle_history",
    getWithdrawPage: "rpc_get_withdraw_page",
    getReferralPage: "rpc_get_referral_page",
    WatchPet: "rpc_get_active_pet"
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
    if (!token) return res.status(401).json({ error: "Missing token" });
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const rpc = USER_RPC_MAP[action];
        if (!rpc) return res.status(400).json({ error: "Unknown action" });
        params.p_telegram_id = payload.telegram_id;
        const { data, error } = await supabase.rpc(rpc, params);
        if (error) return res.status(500).json({ ok: false, error: error.message });
        return res.json({ ok: true, data });
    } catch (err) {
        return res.status(401).json({ error: "INVALID_TOKEN" });
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

// API: Batch Data
app.post("/api/batchData", async (req, res) => {
    const { requests, token } = req.body;
    if (!Array.isArray(requests)) return res.status(400).json({ error: "Invalid requests" });
    if (!token) return res.status(401).json({ error: "Missing token" });
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const results = await Promise.all(requests.map(async (item) => {
            const { rpcName, params = {} } = item;
            params.p_telegram_id = payload.telegram_id;
            const cacheKey = `${rpcName}:user_${payload.telegram_id}`;
            const resData = await getCachedRpc(cacheKey, rpcName, params, 20);
            return { rpcName, data: resData.data };
        }));
        return res.json({ ok: true, data: results });
    } catch (err) {
        return res.status(401).json({ error: "INVALID_TOKEN" });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server chạy mượt mà tại cổng ${PORT}`));
        
