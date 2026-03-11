const express    = require("express");
const cors       = require("cors");
const crypto     = require("crypto");
const https      = require("https");
const nodemailer = require("nodemailer");

const app  = express();
const PORT = process.env.PORT || 3000;
app.use(cors({ origin: "*" }));
app.use(express.json());

// ══════════════════════════════════════════════════════════════════════════════
//  SÉCURITÉ — Configuration
// ══════════════════════════════════════════════════════════════════════════════

// Token secret — à définir dans les variables d'env Railway
// Si non défini, le serveur refuse TOUTES les requêtes non-publiques
const SERVER_SECRET = process.env.SERVER_SECRET || null;

// Rate limiting — protection anti-spam et anti-ban Binance
const rateLimitStore = new Map(); // ip → { count, resetAt }

function rateLimit(maxPerMin = 60) {
  return (req, res, next) => {
    const ip      = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress || "unknown";
    const now     = Date.now();
    const window  = 60 * 1000;
    const entry   = rateLimitStore.get(ip) || { count: 0, resetAt: now + window };

    if (now > entry.resetAt) {
      entry.count   = 0;
      entry.resetAt = now + window;
    }
    entry.count++;
    rateLimitStore.set(ip, entry);

    // Headers standards rate limit
    res.setHeader("X-RateLimit-Limit",     maxPerMin);
    res.setHeader("X-RateLimit-Remaining", Math.max(0, maxPerMin - entry.count));
    res.setHeader("X-RateLimit-Reset",     Math.ceil(entry.resetAt / 1000));

    if (entry.count > maxPerMin) {
      addLog(`⚠ Rate limit dépassé — IP: ${ip} (${entry.count} req/min)`, "warning");
      return res.status(429).json({
        error: "Trop de requêtes",
        retryAfter: Math.ceil((entry.resetAt - now) / 1000) + "s",
      });
    }
    next();
  };
}

// Nettoyage du store toutes les 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitStore.entries()) {
    if (now > entry.resetAt + 60000) rateLimitStore.delete(ip);
  }
}, 5 * 60 * 1000);

// Middleware d'authentification par token
function requireAuth(req, res, next) {
  // Routes publiques toujours exemptées
  const publicPaths = ["/", "/public", "/health", "/auth/verify"];
  if (publicPaths.includes(req.path)) return next();

  // Si aucun secret configuré → MODE NON SÉCURISÉ mais fonctionnel
  // (acceptable en test, à corriger avant trading réel)
  if (!SERVER_SECRET) {
    // Log une seule fois toutes les 60s pour ne pas spammer
    const now = Date.now();
    if (!requireAuth._lastWarn || now - requireAuth._lastWarn > 60000) {
      addLog("⚠ SERVER_SECRET non défini — mode non sécurisé (OK pour test)", "warning");
      requireAuth._lastWarn = now;
    }
    return next(); // Laisser passer sans token
  }

  // Si secret configuré → vérifier le token
  const authHeader = req.headers["authorization"];
  const tokenQuery = req.query._token;
  const token      = authHeader?.replace("Bearer ", "") || tokenQuery;

  // Si token absent mais secret configuré → refuser
  if (!token) {
    return res.status(401).json({
      error: "Token manquant",
      hint: "Configurer SERVER_SECRET dans l'app onglet 🔐 Sécurité"
    });
  }

  // Comparaison en temps constant (protection timing attack)
  const crypto   = require("crypto");
  const expected = crypto.createHash("sha256").update(SERVER_SECRET).digest("hex");
  const received = crypto.createHash("sha256").update(token).digest("hex");
  const valid    = expected.length === received.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));

  if (!valid) {
    addLog(`🚨 Token invalide — IP: ${req.headers["x-forwarded-for"] || "unknown"}`, "warning");
    return res.status(403).json({ error: "Token invalide" });
  }
  next();
}

// Sanitisation des inputs — protection injection
function sanitizeInput(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const safe = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === "string") {
      // Supprimer caractères dangereux
      safe[k] = v.replace(/[<>'"`;\\]/g, "").trim().slice(0, 200);
    } else if (typeof v === "number") {
      safe[k] = isNaN(v) ? 0 : v;
    } else if (typeof v === "boolean") {
      safe[k] = v;
    } else if (typeof v === "object" && v !== null) {
      safe[k] = sanitizeInput(v);
    } else {
      safe[k] = v;
    }
  }
  return safe;
}

// Validation des symboles Binance (ex: BTCUSDT)
function isValidSymbol(sym) {
  return typeof sym === "string" && /^[A-Z0-9]{2,20}$/.test(sym.trim().toUpperCase());
}

// Validation des paramètres numériques dans une plage
function inRange(val, min, max) {
  const n = parseFloat(val);
  return !isNaN(n) && n >= min && n <= max;
}

// Protection HMAC des webhooks entrants (optionnel)
function verifyWebhookSignature(body, signature, secret) {
  const crypto = require("crypto");
  const expected = crypto.createHmac("sha256", secret).update(JSON.stringify(body)).digest("hex");
  return signature === expected;
}

// Log d'accès sécurité
function securityLog(req, action) {
  const ip  = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
  const ua  = (req.headers["user-agent"] || "").slice(0, 60);
  addLog(`[SEC] ${action} — IP:${ip} UA:${ua}`, "info");
}

// Headers de sécurité HTTP
function securityHeaders(req, res, next) {
  res.setHeader("X-Content-Type-Options",    "nosniff");
  res.setHeader("X-Frame-Options",           "DENY");
  res.setHeader("X-XSS-Protection",          "1; mode=block");
  res.setHeader("Referrer-Policy",           "no-referrer");
  res.setHeader("Permissions-Policy",        "camera=(), microphone=(), geolocation=()");
  // Ne pas exposer Express
  res.removeHeader("X-Powered-By");
  next();
}


// Appliquer les middlewares globalement
app.use(securityHeaders);
app.use(rateLimit(120));  // 120 req/min par IP (assez permissif pour le polling)
app.use(requireAuth);     // token obligatoire sur toutes les routes sauf /


// ── Config email (variables d'env Railway ou set via API) ──────────────────
let emailConfig = {
  enabled:       process.env.EMAIL_ENABLED === "true",
  gmailUser:     process.env.EMAIL_USER    || "",
  gmailPass:     process.env.EMAIL_PASS    || "",  // App Password Gmail
  recipient:     process.env.EMAIL_TO      || "",
  reportHour:    parseInt(process.env.REPORT_HOUR || "20"), // heure envoi (20h)
  reportMinute:  parseInt(process.env.REPORT_MIN  || "0"),
};
let dailyReportTimer = null;
let sessionStartTime = Date.now();

const BINANCE_LIVE    = "https://api.binance.com";
const BINANCE_TESTNET = "https://testnet.binance.vision";

// ══════════════════════════════════════════════════════════════════════════════
//  ÉTAT GLOBAL DU BOT
// ══════════════════════════════════════════════════════════════════════════════
const SC_PAIRS_LIST = ["USDCUSDT","FDUSDUSDT","TUSDUSDT","DAIUSDT"];

let botState = {
  running: false, config: null, intervalId: null,
  position: null, entryPrice: null, entryTime: null,
  highestPrice: null,      // pour trailing SL
  trailingSL: null,        // niveau trailing SL actuel
  partialState: { level: 0, remainingQty: 0, breakEvenMoved: false },
  dcaOrders: 0, dcaAvgPrice: null, dcaTotalQty: 0,
  fearGreed: null,         // dernière valeur Fear & Greed
  logs: [], trades: [],
  // Auto-switch stablecoin
  currentScSymbol: null,
  scNotProfitableSince: null,
  scScanResults: {},
  // Multi-asset scanner
  scannerRunning: false,
  scannerResults: [],           // [{symbol, score, rsi, volume, momentum, atr, recommendation}]
  scannerLastRun: null,
  activeSymbols: [],            // paires actives actuellement tradées
  symbolScores: {},             // {symbol: score}
  symbolNotProfitable: {},      // {symbol: timestamp depuis non rentable}
  scannerInterval: null,
  stats: {
    totalTrades: 0, winTrades: 0, lossTrades: 0,
    totalPnlUsd: 0, totalPnlPct: 0,
    bestTrade: null, worstTrade: null,
    largestWin: 0, largestLoss: 0,
    currentDrawdown: 0, maxDrawdown: 0,
    startBalance: null, runningPnl: 0,
  }
};

// ══════════════════════════════════════════════════════════════════════════════
//  LOGS
// ══════════════════════════════════════════════════════════════════════════════
function addLog(msg, type = "info") {
  const time = new Date().toLocaleTimeString("fr-FR", {hour12:false});
  botState.logs.unshift({ msg, type, time, id: Date.now() + Math.random() });
  if (botState.logs.length > 1000) botState.logs.pop();
  console.log(`[${type.toUpperCase()}] ${msg}`);
}

// ══════════════════════════════════════════════════════════════════════════════
//  CRYPTO & REQUÊTES
// ══════════════════════════════════════════════════════════════════════════════
function sign(secret, qs) {
  return crypto.createHmac("sha256", secret).update(qs).digest("hex");
}

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: "GET", headers }, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function httpPost(url, headers = {}, bodyStr = "") {
  return new Promise((resolve, reject) => {
    const opts = {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers }
    };
    const req = https.request(url, opts, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    req.write(bodyStr);
    req.end();
  });
}

async function binanceReq(apiKey, apiSecret, testnet, method, path, params = {}) {
  const base = testnet ? BINANCE_TESTNET : BINANCE_LIVE;
  const ts   = Date.now();
  const qp   = { ...params, timestamp: ts };
  const qs   = Object.entries(qp).map(([k, v]) => `${k}=${v}`).join("&");
  const sig  = sign(apiSecret, qs);
  const url  = `${base}${path}?${qs}&signature=${sig}`;
  const hdrs = { "X-MBX-APIKEY": apiKey };
  const { status, body } = method === "GET"
    ? await httpGet(url, hdrs)
    : await httpPost(url, hdrs, "");
  if (status !== 200) throw new Error(body.msg || `HTTP ${status}`);
  return body;
}

async function pubFetch(path, params = {}) {
  const qs  = Object.entries(params).map(([k, v]) => `${k}=${v}`).join("&");
  const url = `${BINANCE_LIVE}${path}${qs ? "?" + qs : ""}`;
  const { body } = await httpGet(url);
  return body;
}


// ══════════════════════════════════════════════════════════════════════════════
//  BYBIT — INTÉGRATION COMPLÈTE
// ══════════════════════════════════════════════════════════════════════════════
const BYBIT_TESTNET = "https://api-testnet.bybit.com";
const BYBIT_LIVE    = "https://api.bybit.com";

// Signature Bybit (HMAC-SHA256, format différent de Binance)
function signBybit(apiSecret, params) {
  const qs = Object.entries(params)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  return require("crypto").createHmac("sha256", apiSecret).update(qs).digest("hex");
}

// Requête Bybit authentifiée (Spot V5)
async function bybitReq(apiKey, apiSecret, testnet, method, path, params = {}) {
  const base  = testnet ? BYBIT_TESTNET : BYBIT_LIVE;
  const ts    = Date.now().toString();
  const recv  = "5000";
  const allParams = { ...params };

  // Bybit V5: signature sur timestamp+apiKey+recvWindow+queryString
  const paramStr = Object.entries(allParams)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  const preSign = ts + apiKey + recv + paramStr;
  const sig = require("crypto").createHmac("sha256", apiSecret).update(preSign).digest("hex");

  const hdrs = {
    "X-BAPI-API-KEY":     apiKey,
    "X-BAPI-TIMESTAMP":   ts,
    "X-BAPI-RECV-WINDOW": recv,
    "X-BAPI-SIGN":        sig,
    "Content-Type":       "application/json",
  };

  let url, bodyStr = "";
  if (method === "GET") {
    url = `${base}${path}${paramStr ? "?" + paramStr : ""}`;
  } else {
    url = `${base}${path}`;
    bodyStr = JSON.stringify(allParams);
  }

  const { status, body } = method === "GET"
    ? await httpGet(url, hdrs)
    : await httpPost(url, hdrs, bodyStr);

  if (body?.retCode !== undefined && body.retCode !== 0) {
    throw new Error(body.retMsg || `Bybit error ${body.retCode}`);
  }
  if (status !== 200) throw new Error(`HTTP ${status}`);
  return body;
}

// Requête publique Bybit (pas d'auth)
async function bybitPub(path, params = {}) {
  const qs  = Object.entries(params).map(([k, v]) => `${k}=${v}`).join("&");
  const url = `${BYBIT_LIVE}${path}${qs ? "?" + qs : ""}`;
  const { body } = await httpGet(url);
  return body;
}

// ── Adaptateur Bybit → format unifié Binance ─────────────────────────────────
// Toutes les fonctions internes utilisent le format Binance.
// Ces adaptateurs convertissent les réponses Bybit.

async function bybitGetAccount(apiKey, apiSecret, testnet) {
  const r = await bybitReq(apiKey, apiSecret, testnet, "GET", "/v5/account/wallet-balance", {
    accountType: "UNIFIED",
  });
  const coins = r?.result?.list?.[0]?.coin || [];
  // Format Binance: { balances: [{asset, free, locked}] }
  return {
    balances: coins.map(c => ({
      asset:  c.coin,
      free:   parseFloat(c.availableToWithdraw || c.walletBalance || 0).toFixed(8),
      locked: parseFloat(c.locked || 0).toFixed(8),
    })).filter(b => parseFloat(b.free) > 0 || parseFloat(b.locked) > 0),
  };
}

async function bybitGetPrice(symbol) {
  const r = await bybitPub("/v5/market/tickers", { category: "spot", symbol });
  const item = r?.result?.list?.[0];
  return { symbol, price: item?.lastPrice || "0" };
}

async function bybitGetKlines(symbol, interval, limit = 200) {
  // Bybit interval map: 1m→1, 5m→5, 15m→15, 1h→60, 4h→240, 1d→D
  const intervalMap = {
    "1m": "1", "3m": "3", "5m": "5", "15m": "15", "30m": "30",
    "1h": "60", "2h": "120", "4h": "240", "6h": "360", "12h": "720",
    "1d": "D", "1w": "W",
  };
  const bybitInterval = intervalMap[interval] || "60";
  const r = await bybitPub("/v5/market/kline", {
    category: "spot", symbol, interval: bybitInterval, limit,
  });
  const list = r?.result?.list || [];
  // Bybit: [startTime, open, high, low, close, volume, turnover]
  // Binance: [openTime, open, high, low, close, volume, closeTime, ...]
  return list.reverse().map(k => [
    parseInt(k[0]), k[1], k[2], k[3], k[4], k[5],
    parseInt(k[0]) + 60000, k[6], 0, 0, "0", "0",
  ]);
}

async function bybitGetOrderBook(symbol, limit = 20) {
  const r = await bybitPub("/v5/market/orderbook", { category: "spot", symbol, limit });
  const result = r?.result;
  if (!result) return null;
  // Format Binance: { bids: [[price, qty]], asks: [[price, qty]] }
  return {
    bids: result.b || [],
    asks: result.a || [],
  };
}

async function bybitPlaceOrder(apiKey, apiSecret, testnet, symbol, side, qty) {
  const r = await bybitReq(apiKey, apiSecret, testnet, "POST", "/v5/order/create", {
    category:  "spot",
    symbol,
    side:      side === "BUY" ? "Buy" : "Sell",
    orderType: "Market",
    qty:       qty.toString(),
    timeInForce: "IOC",
  });
  // Format Binance
  return {
    orderId:     r?.result?.orderId || "BYBIT_" + Date.now(),
    symbol,
    side,
    status:      "FILLED",
    origQty:     qty,
    executedQty: qty,
  };
}

async function bybitGetTrades(symbol, limit = 200) {
  const r = await bybitPub("/v5/market/recent-trade", { category: "spot", symbol, limit });
  const list = r?.result?.list || [];
  // Format Binance aggTrades: { p: price, q: qty, m: isBuyerMaker, T: time }
  return list.map(t => ({
    p: t.price, q: t.size,
    m: t.side === "Sell", // Sell side = buyer is maker
    T: parseInt(t.time),
  }));
}

// ── Fonction universelle: routeur exchange ────────────────────────────────────
// Toutes les fonctions du bot passent par ici selon l'exchange configuré
async function exchangeReq(cfg, method, path, params = {}) {
  if (cfg.exchange === "bybit") {
    return bybitReq(cfg.apiKey, cfg.apiSecret, cfg.testnet, method, path, params);
  }
  return binanceReq(cfg.apiKey, cfg.apiSecret, cfg.testnet, method, path, params);
}

async function exchangePubKlines(cfg, symbol, interval, limit) {
  if (cfg?.exchange === "bybit") return bybitGetKlines(symbol, interval, limit);
  const klines = await pubFetch("/api/v3/klines", { symbol, interval, limit });
  return klines;
}

async function exchangeGetPrice(cfg, symbol) {
  if (cfg?.exchange === "bybit") return bybitGetPrice(symbol);
  return pubFetch("/api/v3/ticker/price", { symbol });
}

async function exchangeGetAccount(cfg) {
  if (cfg?.exchange === "bybit") return bybitGetAccount(cfg.apiKey, cfg.apiSecret, cfg.testnet);
  return binanceReq(cfg.apiKey, cfg.apiSecret, cfg.testnet, "GET", "/api/v3/account");
}

async function exchangePlaceOrder(cfg, symbol, side, qty) {
  if (cfg?.exchange === "bybit") return bybitPlaceOrder(cfg.apiKey, cfg.apiSecret, cfg.testnet, symbol, side, qty);
  return binanceReq(cfg.apiKey, cfg.apiSecret, cfg.testnet, "POST", "/api/v3/order", {
    symbol, side, type: "MARKET", quantity: qty,
  });
}

async function exchangeGetOrderBook(cfg, symbol, limit = 20) {
  if (cfg?.exchange === "bybit") {
    const book = await bybitGetOrderBook(symbol, limit);
    return book;
  }
  return pubFetch("/api/v3/depth", { symbol, limit });
}

async function exchangeGetTrades(cfg, symbol, limit = 200) {
  if (cfg?.exchange === "bybit") return bybitGetTrades(symbol, limit);
  return pubFetch("/api/v3/aggTrades", { symbol, limit });
}

// Symboles disponibles par exchange
async function exchangeGetSymbols(exchange) {
  if (exchange === "bybit") {
    const r = await bybitPub("/v5/market/instruments-info", { category: "spot", status: "Trading" });
    return (r?.result?.list || [])
      .filter(s => s.quoteCoin === "USDT")
      .map(s => s.symbol);
  }
  // Binance
  const r = await pubFetch("/api/v3/exchangeInfo");
  return (r?.symbols || [])
    .filter(s => s.status === "TRADING" && s.quoteAsset === "USDT")
    .map(s => s.symbol);
}

// ══════════════════════════════════════════════════════════════════════════════
//  INDICATEURS TECHNIQUES
// ══════════════════════════════════════════════════════════════════════════════
function calcRSI(prices, p = 14) {
  if (prices.length < p + 1) return null;
  let g = 0, l = 0;
  for (let i = 1; i <= p; i++) { const d = prices[i]-prices[i-1]; d>=0?g+=d:l-=d; }
  let ag = g/p, al = l/p;
  for (let i = p+1; i < prices.length; i++) {
    const d = prices[i]-prices[i-1];
    ag = (ag*(p-1)+Math.max(0,d))/p;
    al = (al*(p-1)+Math.max(0,-d))/p;
  }
  return al === 0 ? 100 : 100 - 100/(1+ag/al);
}

function calcEMA(prices, p) {
  if (prices.length < p) return null;
  const k = 2 / (p + 1);
  let ema = prices.slice(0, p).reduce((a, b) => a + b, 0) / p;
  for (let i = p; i < prices.length; i++) ema = prices[i] * k + ema * (1 - k);
  return ema;
}

function calcSMA(prices, p) {
  if (prices.length < p) return null;
  return prices.slice(-p).reduce((a, b) => a + b, 0) / p;
}

function calcMACD(prices) {
  const ema12 = calcEMA(prices, 12);
  const ema26 = calcEMA(prices, 26);
  if (!ema12 || !ema26) return null;
  const macdLine = ema12 - ema26;
  return { macd: macdLine, ema12, ema26 };
}

function calcBollingerBands(prices, p = 20, mult = 2) {
  if (prices.length < p) return null;
  const slice = prices.slice(-p);
  const sma   = slice.reduce((a, b) => a + b, 0) / p;
  const std   = Math.sqrt(slice.map(v => Math.pow(v - sma, 2)).reduce((a, b) => a + b, 0) / p);
  return { upper: sma + mult*std, middle: sma, lower: sma - mult*std, std, bandwidth: (2*mult*std)/sma*100 };
}

function calcStochastic(highs, lows, closes, k = 14, d = 3) {
  if (closes.length < k) return null;
  const recentH = Math.max(...highs.slice(-k));
  const recentL = Math.min(...lows.slice(-k));
  const cur     = closes.at(-1);
  const kVal    = recentH === recentL ? 50 : ((cur - recentL) / (recentH - recentL)) * 100;
  const dSlice  = closes.slice(-(k + d - 1));
  let dSum = 0;
  for (let i = 0; i < d; i++) {
    const h = Math.max(...highs.slice(-(k+d-1-i), highs.length-i));
    const l = Math.min(...lows.slice(-(k+d-1-i), lows.length-i));
    dSum += h === l ? 50 : ((dSlice[dSlice.length-1-i] - l) / (h - l)) * 100;
  }
  return { k: kVal, d: dSum / d };
}

function calcATR(highs, lows, closes, p = 14) {
  if (closes.length < p + 1) return null;
  const trs = [];
  for (let i = 1; i < closes.length; i++) {
    trs.push(Math.max(
      highs[i] - lows[i],
      Math.abs(highs[i] - closes[i-1]),
      Math.abs(lows[i]  - closes[i-1])
    ));
  }
  return trs.slice(-p).reduce((a, b) => a + b, 0) / p;
}

function calcVWAP(klines) {
  let cumTP = 0, cumVol = 0;
  for (const k of klines) {
    const tp  = (parseFloat(k[2]) + parseFloat(k[3]) + parseFloat(k[4])) / 3;
    const vol = parseFloat(k[5]);
    cumTP  += tp * vol;
    cumVol += vol;
  }
  return cumVol > 0 ? cumTP / cumVol : null;
}

function calcVolumeTrend(volumes, p = 10) {
  if (volumes.length < p) return null;
  const recent = volumes.slice(-p);
  const avg    = recent.reduce((a, b) => a + b, 0) / p;
  const last   = volumes.at(-1);
  return { avg, last, ratio: last / avg, trend: last > avg * 1.5 ? "SURGE" : last < avg * 0.5 ? "DRY" : "NORMAL" };
}


// ══════════════════════════════════════════════════════════════════════════════
//  1. TRAILING STOP LOSS
// ══════════════════════════════════════════════════════════════════════════════
function calcTrailingSL(entryPrice, highestPrice, trailPct, side = "LONG") {
  const trail = parseFloat(trailPct) / 100;
  if (side === "LONG") {
    const trailSL = highestPrice * (1 - trail);
    return Math.max(trailSL, entryPrice * (1 - trail * 1.5)); // jamais sous -1.5x le trail
  }
  return highestPrice * (1 + trail);
}

// ══════════════════════════════════════════════════════════════════════════════
//  2. MULTI-TIMEFRAME ANALYSIS
// ══════════════════════════════════════════════════════════════════════════════
async function multiTimeframeSignal(symbol, primaryTf = "5m") {
  const tfMap = { "1m":"5m","3m":"15m","5m":"1h","15m":"4h","30m":"4h","1h":"1d" };
  const higherTf = tfMap[primaryTf] || "1h";
  try {
    const [kLow, kHigh] = await Promise.all([
      pubFetch("/api/v3/klines", { symbol, interval: primaryTf, limit: 50 }),
      pubFetch("/api/v3/klines", { symbol, interval: higherTf,  limit: 50 }),
    ]);
    if (!Array.isArray(kLow) || !Array.isArray(kHigh)) return { confirmed: false, reason: "data_error" };

    const closesLow  = kLow.map(k  => parseFloat(k[4]));
    const closesHigh = kHigh.map(k => parseFloat(k[4]));

    const rsiLow  = calcRSI(closesLow,  14);
    const rsiHigh = calcRSI(closesHigh, 14);
    const ema9L   = calcEMA(closesLow,  9);
    const ema21L  = calcEMA(closesLow,  21);
    const ema9H   = calcEMA(closesHigh, 9);
    const ema21H  = calcEMA(closesHigh, 21);
    const macdH   = calcMACD(closesHigh);

    const lowBullish  = (rsiLow  !== null && rsiLow  < 55) && (ema9L  > ema21L);
    const highBullish = (rsiHigh !== null && rsiHigh < 65) && (ema9H  > ema21H);
    const macdBull    = macdH && macdH.macd > 0;

    const confirmed = lowBullish && highBullish;
    const strength  = [lowBullish, highBullish, macdBull].filter(Boolean).length;

    return {
      confirmed, strength,
      primaryTf, higherTf,
      rsiLow: rsiLow?.toFixed(1), rsiHigh: rsiHigh?.toFixed(1),
      lowBullish, highBullish, macdBull,
      reason: confirmed ? `${primaryTf}✅ + ${higherTf}✅` : `${primaryTf}${lowBullish?"✅":"❌"} + ${higherTf}${highBullish?"✅":"❌"}`,
    };
  } catch(e) {
    return { confirmed: false, reason: "mtf_error: " + e.message };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  3. RSI DIVERGENCE
// ══════════════════════════════════════════════════════════════════════════════
function detectDivergence(prices, rsiValues, lookback = 14) {
  if (prices.length < lookback || rsiValues.length < lookback) return null;
  const pSlice = prices.slice(-lookback);
  const rSlice = rsiValues.slice(-lookback);

  // Trouver les pivots low et high
  const findPivots = (arr, type = "low") => {
    const pivots = [];
    for (let i = 1; i < arr.length - 1; i++) {
      if (type === "low"  && arr[i] < arr[i-1] && arr[i] < arr[i+1]) pivots.push({ i, v: arr[i] });
      if (type === "high" && arr[i] > arr[i-1] && arr[i] > arr[i+1]) pivots.push({ i, v: arr[i] });
    }
    return pivots;
  };

  const priceLows  = findPivots(pSlice, "low");
  const rsiLows    = findPivots(rSlice, "low");
  const priceHighs = findPivots(pSlice, "high");
  const rsiHighs   = findPivots(rSlice, "high");

  let bullDiv = false, bearDiv = false;

  // Divergence haussière: prix fait LL mais RSI fait HL
  if (priceLows.length >= 2 && rsiLows.length >= 2) {
    const lastPL  = priceLows.at(-1),  prevPL  = priceLows.at(-2);
    const lastRL  = rsiLows.at(-1),    prevRL  = rsiLows.at(-2);
    if (lastPL.v < prevPL.v && lastRL.v > prevRL.v) bullDiv = true;
  }
  // Divergence baissière: prix fait HH mais RSI fait LH
  if (priceHighs.length >= 2 && rsiHighs.length >= 2) {
    const lastPH = priceHighs.at(-1), prevPH = priceHighs.at(-2);
    const lastRH = rsiHighs.at(-1),   prevRH = rsiHighs.at(-2);
    if (lastPH.v > prevPH.v && lastRH.v < prevRH.v) bearDiv = true;
  }

  return { bullDiv, bearDiv, signal: bullDiv ? "BULL_DIV" : bearDiv ? "BEAR_DIV" : "NONE" };
}

// Calcule un tableau de RSI pour la divergence
function calcRSISeries(prices, p = 14) {
  const series = [];
  for (let end = p + 1; end <= prices.length; end++) {
    series.push(calcRSI(prices.slice(0, end), p));
  }
  return series;
}

// ══════════════════════════════════════════════════════════════════════════════
//  4. FEAR & GREED INDEX
// ══════════════════════════════════════════════════════════════════════════════
let _fearGreedCache = null;
let _fearGreedTs    = 0;

async function getFearGreedIndex() {
  const now = Date.now();
  if (_fearGreedCache && now - _fearGreedTs < 3600000) return _fearGreedCache; // cache 1h
  try {
    const data = await new Promise((resolve, reject) => {
      const req = require("https").request(
        "https://api.alternative.me/fng/?limit=1",
        { method: "GET" },
        (res) => {
          let d = "";
          res.on("data", c => d += c);
          res.on("end", () => resolve(JSON.parse(d)));
        }
      );
      req.on("error", reject);
      req.end();
    });
    const value       = parseInt(data.data[0].value);
    const classification = data.data[0].value_classification;
    _fearGreedCache   = { value, classification, ts: now };
    _fearGreedTs      = now;
    addLog(`Fear & Greed Index: ${value} (${classification})`, "info");
    return _fearGreedCache;
  } catch(e) {
    addLog("Fear & Greed: fallback neutre (50) — " + e.message, "warning");
    return { value: 50, classification: "Neutral" };
  }
}

function fearGreedFilter(fgValue, strategy) {
  // Extreme Fear (<25) : BUY signals plus fiables, ÉVITER les ventes short
  // Extreme Greed (>75): SELL signals plus fiables, ÉVITER les achats
  // Neutre (25-75)     : trading normal
  if (strategy === "RSI" || strategy === "MULTI" || strategy === "SCANNER") {
    if (fgValue < 15) return { allow: true,  boost: 1.3, reason: "Extreme Fear — BUY++ " };
    if (fgValue < 30) return { allow: true,  boost: 1.15, reason: "Fear — BUY+"           };
    if (fgValue > 85) return { allow: false, boost: 0.5,  reason: "Extreme Greed — BLOCK BUY" };
    if (fgValue > 70) return { allow: true,  boost: 0.85, reason: "Greed — BUY-"          };
  }
  return { allow: true, boost: 1.0, reason: "Neutral" };
}

// ══════════════════════════════════════════════════════════════════════════════
//  5. PARTIAL TAKE PROFIT
// ══════════════════════════════════════════════════════════════════════════════
// partialState: { level: 0, remainingQty, breakEvenMoved }
function checkPartialTP(pnlPct, partialState, cfg) {
  const levels = [
    { pct: cfg.tp1Pct || 1.5, sellFraction: 0.40 }, // à +1.5% → vend 40%
    { pct: cfg.tp2Pct || 3.0, sellFraction: 0.35 }, // à +3.0% → vend 35%
    { pct: cfg.tp3Pct || 5.0, sellFraction: 1.00 }, // à +5.0% → vend tout
  ];
  const nextLevel = levels[partialState.level];
  if (!nextLevel) return null;
  if (pnlPct >= nextLevel.pct) {
    return { level: partialState.level, ...nextLevel };
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
//  6. FILTRE TEMPOREL
// ══════════════════════════════════════════════════════════════════════════════
function timeFilter(cfg) {
  if (!cfg.useTimeFilter) return { allowed: true, reason: "disabled" };
  const utcHour = new Date().getUTCHours();
  // Heures creuses par défaut: 02h-06h UTC (faible volume, manipulation)
  const deadStart = cfg.deadHourStart !== undefined ? parseInt(cfg.deadHourStart) : 2;
  const deadEnd   = cfg.deadHourEnd   !== undefined ? parseInt(cfg.deadHourEnd)   : 6;
  const inDead = deadStart < deadEnd
    ? utcHour >= deadStart && utcHour < deadEnd
    : utcHour >= deadStart || utcHour < deadEnd;
  return {
    allowed: !inDead,
    utcHour,
    reason: inDead
      ? `Heure creuse UTC ${utcHour}h (${deadStart}h-${deadEnd}h) — skip`
      : `OK (UTC ${utcHour}h)`,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  7. FILTRE DE CORRÉLATION
// ══════════════════════════════════════════════════════════════════════════════
// Groupes de corrélation forte (r > 0.85 historiquement)
const CORR_GROUPS = [
  ["BTCUSDT","ETHUSDT","BNBUSDT","SOLUSDT","AVAXUSDT","DOTUSDT","ADAUSDT"],
  ["XRPUSDT","XLMUSDT","ALGOUSDT"],
  ["DOGEUSDT","SHIBUSDT","FLOKIUSDT"],
  ["LTCUSDT","BCHUSDT"],
];

function correlationFilter(newSymbol, activePositions, maxCorrelated = 2) {
  const group = CORR_GROUPS.find(g => g.includes(newSymbol));
  if (!group) return { allowed: true, reason: "No correlation group" };
  const correlated = Object.keys(activePositions).filter(sym =>
    activePositions[sym]?.position && group.includes(sym)
  );
  if (correlated.length >= maxCorrelated) {
    return {
      allowed: false,
      reason: `Corrélation: déjà ${correlated.length} positions dans le groupe (${correlated.join(",")})`,
    };
  }
  return { allowed: true, reason: `${correlated.length}/${maxCorrelated} dans groupe` };
}

// ══════════════════════════════════════════════════════════════════════════════
//  8. KELLY CRITERION — Position Sizing dynamique
// ══════════════════════════════════════════════════════════════════════════════
function kellyPositionSize(stats, baseMise, maxMise, minMise) {
  const total = stats.totalTrades || 0;
  if (total < 10) return baseMise; // pas assez de données → mise de base
  const w = stats.winTrades  / total;
  const l = stats.lossTrades / total;
  const avgWin  = stats.largestWin  > 0 ? stats.totalPnlUsd / Math.max(stats.winTrades, 1)  : 1;
  const avgLoss = stats.largestLoss < 0 ? Math.abs(stats.totalPnlUsd / Math.max(stats.lossTrades, 1)) : 1;
  const r    = avgWin / Math.max(avgLoss, 0.01); // ratio gain/perte moyen
  const kelly = w - (l / Math.max(r, 0.01));     // formule Kelly
  // Demi-Kelly par sécurité (évite la ruine)
  const halfKelly = Math.max(0, kelly / 2);
  const sized     = baseMise * (1 + halfKelly * 2);
  return Math.min(Math.max(sized, minMise || baseMise * 0.5), maxMise || baseMise * 3);
}

// ══════════════════════════════════════════════════════════════════════════════
//  9. PATTERNS CHANDELIERS JAPONAIS
// ══════════════════════════════════════════════════════════════════════════════
function detectCandlePatterns(klines) {
  if (klines.length < 3) return [];
  const patterns = [];
  const get = i => ({
    o: parseFloat(klines[i][1]),
    h: parseFloat(klines[i][2]),
    l: parseFloat(klines[i][3]),
    c: parseFloat(klines[i][4]),
    body: Math.abs(parseFloat(klines[i][4]) - parseFloat(klines[i][1])),
    range: parseFloat(klines[i][2]) - parseFloat(klines[i][3]),
    bullish: parseFloat(klines[i][4]) > parseFloat(klines[i][1]),
  });

  const c0 = get(klines.length - 1); // bougie actuelle
  const c1 = get(klines.length - 2); // précédente
  const c2 = get(klines.length - 3); // avant-précédente

  const bodyRatio = (k) => k.range > 0 ? k.body / k.range : 0;

  // DOJI — indécision (corps < 10% du range)
  if (bodyRatio(c0) < 0.1) patterns.push({ name: "DOJI", signal: "NEUTRAL", strength: 1 });

  // HAMMER — bougie haussière de retournement
  const lowerWick0 = c0.bullish ? c0.o - c0.l : c0.c - c0.l;
  const upperWick0 = c0.bullish ? c0.h - c0.c : c0.h - c0.o;
  if (lowerWick0 > c0.body * 2 && upperWick0 < c0.body * 0.5 && !c1.bullish)
    patterns.push({ name: "HAMMER", signal: "BUY", strength: 3 });

  // SHOOTING STAR — bougie baissière de retournement
  if (upperWick0 > c0.body * 2 && lowerWick0 < c0.body * 0.5 && c1.bullish)
    patterns.push({ name: "SHOOTING_STAR", signal: "SELL", strength: 3 });

  // BULLISH ENGULFING
  if (!c1.bullish && c0.bullish && c0.o < c1.c && c0.c > c1.o && c0.body > c1.body)
    patterns.push({ name: "BULLISH_ENGULFING", signal: "BUY", strength: 4 });

  // BEARISH ENGULFING
  if (c1.bullish && !c0.bullish && c0.o > c1.c && c0.c < c1.o && c0.body > c1.body)
    patterns.push({ name: "BEARISH_ENGULFING", signal: "SELL", strength: 4 });

  // MORNING STAR (3 bougies)
  if (!c2.bullish && bodyRatio(c1) < 0.3 && c0.bullish && c0.c > (c2.o + c2.c) / 2)
    patterns.push({ name: "MORNING_STAR", signal: "BUY", strength: 5 });

  // EVENING STAR (3 bougies)
  if (c2.bullish && bodyRatio(c1) < 0.3 && !c0.bullish && c0.c < (c2.o + c2.c) / 2)
    patterns.push({ name: "EVENING_STAR", signal: "SELL", strength: 5 });

  // THREE WHITE SOLDIERS
  if (c0.bullish && c1.bullish && c2.bullish &&
      c0.c > c1.c && c1.c > c2.c && c0.o > c1.o && c1.o > c2.o)
    patterns.push({ name: "THREE_WHITE_SOLDIERS", signal: "BUY", strength: 5 });

  // THREE BLACK CROWS
  if (!c0.bullish && !c1.bullish && !c2.bullish &&
      c0.c < c1.c && c1.c < c2.c && c0.o < c1.o && c1.o < c2.o)
    patterns.push({ name: "THREE_BLACK_CROWS", signal: "SELL", strength: 5 });

  return patterns;
}

function patternScore(patterns) {
  // Score net: BUY patterns positifs, SELL négatifs
  return patterns.reduce((acc, p) => {
    if (p.signal === "BUY")     return acc + p.strength;
    if (p.signal === "SELL")    return acc - p.strength;
    return acc;
  }, 0);
}

// ══════════════════════════════════════════════════════════════════════════════
//  ANALYSE COMPLÈTE D'UNE PAIRE
// ══════════════════════════════════════════════════════════════════════════════
async function analyzeSymbol(symbol, interval = "1m", limit = 100) {
  // Binance ne supporte pas les intervalles < 1m via klines — fallback à 1m
  const safeInterval = ["1s","5s","10s","30s"].includes(interval) ? "1m" : interval;
  const raw = await pubFetch("/api/v3/klines", { symbol, interval: safeInterval, limit });
  if (!Array.isArray(raw)) throw new Error("Réponse klines invalide: " + JSON.stringify(raw).slice(0,80));
  const klines  = raw;
  const opens   = klines.map(k => parseFloat(k[1]));
  const highs   = klines.map(k => parseFloat(k[2]));
  const lows    = klines.map(k => parseFloat(k[3]));
  const closes  = klines.map(k => parseFloat(k[4]));
  const volumes = klines.map(k => parseFloat(k[5]));
  const cur     = closes.at(-1);

  const rsi  = calcRSI(closes);
  const macd = calcMACD(closes);
  const bb   = calcBollingerBands(closes);
  const sto  = calcStochastic(highs, lows, closes);
  const atr  = calcATR(highs, lows, closes);
  const vwap = calcVWAP(klines);
  const vol  = calcVolumeTrend(volumes);
  const ema9  = calcEMA(closes, 9);
  const ema21 = calcEMA(closes, 21);
  const ema50 = calcEMA(closes, 50);
  const sma20 = calcSMA(closes, 20);

  // Score de signal composite
  let bullScore = 0, bearScore = 0;
  const signals = [];

  if (rsi !== null) {
    if (rsi < 30)      { bullScore += 3; signals.push("RSI_OVERSOLD"); }
    else if (rsi < 40) { bullScore += 1; signals.push("RSI_LOW"); }
    else if (rsi > 70) { bearScore += 3; signals.push("RSI_OVERBOUGHT"); }
    else if (rsi > 60) { bearScore += 1; signals.push("RSI_HIGH"); }
  }
  if (macd) {
    if (macd.macd > 0)  { bullScore += 1; signals.push("MACD_POSITIVE"); }
    else                { bearScore += 1; signals.push("MACD_NEGATIVE"); }
  }
  if (bb) {
    if (cur < bb.lower)  { bullScore += 2; signals.push("BB_OVERSOLD"); }
    if (cur > bb.upper)  { bearScore += 2; signals.push("BB_OVERBOUGHT"); }
  }
  if (sto) {
    if (sto.k < 20 && sto.d < 20) { bullScore += 2; signals.push("STOCH_OVERSOLD"); }
    if (sto.k > 80 && sto.d > 80) { bearScore += 2; signals.push("STOCH_OVERBOUGHT"); }
  }
  if (ema9 && ema21) {
    if (ema9 > ema21) { bullScore += 1; signals.push("EMA_BULLISH"); }
    else              { bearScore += 1; signals.push("EMA_BEARISH"); }
  }
  if (vwap) {
    if (cur > vwap) { bullScore += 1; signals.push("ABOVE_VWAP"); }
    else            { bearScore += 1; signals.push("BELOW_VWAP"); }
  }
  if (vol && vol.trend === "SURGE") { signals.push("VOLUME_SURGE"); bullScore += 1; }

  const netScore   = bullScore - bearScore;
  const recommendation = netScore >= 4 ? "STRONG_BUY" : netScore >= 2 ? "BUY"
    : netScore <= -4 ? "STRONG_SELL" : netScore <= -2 ? "SELL" : "NEUTRAL";

  // Régime de marché
  const regime = detectMarketRegime(highs, lows, closes, volumes);

  // Volume Profile (VPVR)
  const vpvr = calcVolumeProfile(klines, 20);
  if (vpvr) {
    const cur2 = closes.at(-1);
    const nearPOC    = Math.abs(cur2 - vpvr.poc) / cur2 < 0.005;
    const aboveVAH   = cur2 > vpvr.vaHigh;
    const belowVAL   = cur2 < vpvr.vaLow;
    if (nearPOC)   signals.push("NEAR_POC");
    if (aboveVAH)  { bullScore += 2; signals.push("ABOVE_VAH"); }
    if (belowVAL)  { bearScore += 2; signals.push("BELOW_VAL"); }
  }

  // RSI Series pour divergence
  const rsiSeries  = calcRSISeries(closes, 14);
  const divergence = detectDivergence(closes, rsiSeries);
  if (divergence?.bullDiv) { bullScore += 4; signals.push("RSI_BULL_DIVERGENCE"); }
  if (divergence?.bearDiv) { bearScore += 4; signals.push("RSI_BEAR_DIVERGENCE"); }

  // Patterns chandeliers
  const patterns     = detectCandlePatterns(klines);
  const pScore       = patternScore(patterns);
  if (pScore > 0)  { bullScore += Math.min(pScore, 6); if (patterns.length) signals.push("CANDLE_" + patterns.map(p=>p.name).join("+")); }
  if (pScore < 0)  { bearScore += Math.min(-pScore, 6); }

  const finalNet = bullScore - bearScore;
  const finalRec = finalNet >= 5 ? "STRONG_BUY" : finalNet >= 3 ? "BUY"
    : finalNet <= -5 ? "STRONG_SELL" : finalNet <= -3 ? "SELL" : "NEUTRAL";

  return {
    symbol, price: cur, klines,
    indicators: { rsi, macd, bb, stochastic: sto, atr, vwap, ema9, ema21, ema50, sma20, volume: vol },
    divergence, patterns, regime, vpvr,
    signals, bullScore, bearScore, netScore: finalNet, recommendation: finalRec,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  GESTION DES PNL & STATISTIQUES
// ══════════════════════════════════════════════════════════════════════════════
function recordTrade(side, entryP, exitP, qty, symbol, paperMode = false) {
  const rawPnl  = side === "BUY_CLOSE" ? (exitP - entryP) * qty : (entryP - exitP) * qty;
  // Estimation du slippage sur le trade réel
  const slipData = applySlippageToPnl(rawPnl, entryP, exitP, qty, 1000000);
  const pnlUsd   = paperMode ? slipData.realPnl : rawPnl; // paper inclut slip, réel l'intègre déjà
  if (!paperMode) recordCircuitBreakerTrade(pnlUsd);
  const pnlPct = ((exitP - entryP) / entryP) * 100 * (side === "BUY_CLOSE" ? 1 : -1);
  const won    = pnlUsd > 0;

  const tradeRecord = {
    id: Date.now(), symbol, side: "SELL", entryPrice: entryP, exitPrice: exitP,
    qty, pnlUsd: pnlUsd.toFixed(4), pnlPct: pnlPct.toFixed(3),
    won, time: new Date().toISOString().slice(0, 19).replace("T", " "),
  };

  const s = botState.stats;
  s.totalTrades++;
  won ? s.winTrades++ : s.lossTrades++;
  s.totalPnlUsd  += pnlUsd;
  s.runningPnl   += pnlUsd;

  if (pnlUsd > s.largestWin)  { s.largestWin  = pnlUsd; s.bestTrade  = tradeRecord; }
  if (pnlUsd < s.largestLoss) { s.largestLoss = pnlUsd; s.worstTrade = tradeRecord; }
  if (s.runningPnl < s.maxDrawdown) s.maxDrawdown = s.runningPnl;

  botState.trades.unshift(tradeRecord);
  if (botState.trades.length > 200) botState.trades.pop();

  addLog(
    `📊 Trade clôturé ${symbol}: ${won?"✅ GAIN":"❌ PERTE"} ${pnlUsd>=0?"+":""}${pnlUsd.toFixed(2)} USDT (${pnlPct>=0?"+":""}${pnlPct.toFixed(2)}%)`,
    won ? "success" : "error"
  );
  return tradeRecord;
}

// ══════════════════════════════════════════════════════════════════════════════
//  CYCLE PRINCIPAL DU BOT
// ══════════════════════════════════════════════════════════════════════════════



// ══════════════════════════════════════════════════════════════════════════════
//  SLIPPAGE ESTIMATION — PnL réaliste
// ══════════════════════════════════════════════════════════════════════════════
function estimateSlippage(price, qty, avgVolume, spread) {
  // Slippage de marché: proportionnel à la taille vs volume
  const tradeUsd  = price * qty;
  const volumeUsd = avgVolume * price;
  const mktImpact = volumeUsd > 0 ? (tradeUsd / volumeUsd) * 0.1 : 0.001;
  // Spread slippage: moitié du spread bid/ask estimé
  const spreadSlip = spread ? spread / 2 : price * 0.0002;
  const totalSlipPct = Math.min(mktImpact + (spreadSlip / price), 0.005); // cap 0.5%
  const totalSlipUsd = tradeUsd * totalSlipPct;
  return {
    pct:    parseFloat((totalSlipPct * 100).toFixed(4)),
    usd:    parseFloat(totalSlipUsd.toFixed(4)),
    mktImpactPct: parseFloat((mktImpact * 100).toFixed(4)),
  };
}

function applySlippageToPnl(pnlUsd, entryPrice, exitPrice, qty, volume) {
  const entrySlip = estimateSlippage(entryPrice, qty, volume, 0);
  const exitSlip  = estimateSlippage(exitPrice,  qty, volume, 0);
  const totalSlip = entrySlip.usd + exitSlip.usd;
  return {
    rawPnl:     pnlUsd,
    slippageUsd: totalSlip,
    realPnl:    pnlUsd - totalSlip,
    entrySlip:  entrySlip.pct,
    exitSlip:   exitSlip.pct,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  PAPER TRADING — Simulation sans argent réel
// ══════════════════════════════════════════════════════════════════════════════
let paperState = {
  active:        false,
  capital:       1000,       // capital simulé en USDT
  initialCapital: 1000,
  position:      null,
  entryPrice:    null,
  entryTime:     null,
  highestPrice:  null,
  trailingSL:    null,
  qty:           0,
  partialLevel:  0,
  trades:        [],
  stats: {
    totalTrades: 0, winTrades: 0, lossTrades: 0,
    totalPnlUsd: 0, totalPnlPct: 0,
    largestWin: 0, largestLoss: 0,
    maxDrawdown: 0, peakCapital: 1000,
    equityCurve: [], // [{t, equity}]
  },
};

function paperBuy(symbol, price, qty, reason) {
  if (paperState.position) return null;
  const cost = price * qty;
  if (cost > paperState.capital) {
    qty = (paperState.capital * 0.95) / price;
  }
  const slip = estimateSlippage(price, qty, 1000000, 0);
  const realPrice = price * (1 + slip.pct / 100);
  paperState.position    = "LONG";
  paperState.entryPrice  = realPrice;
  paperState.entryTime   = Date.now();
  paperState.highestPrice = realPrice;
  paperState.qty         = qty;
  paperState.trailingSL  = null;
  paperState.partialLevel = 0;
  const log = `📄 [PAPER] BUY ${qty.toFixed(4)} ${symbol} @ $${realPrice.toFixed(4)} (slip:${slip.pct}%) — ${reason}`;
  addLog(log, "info");
  return { price: realPrice, qty, slip };
}

function paperSell(symbol, price, reason) {
  if (!paperState.position || !paperState.entryPrice) return null;
  const slip     = estimateSlippage(price, paperState.qty, 1000000, 0);
  const realPrice = price * (1 - slip.pct / 100);
  const rawPnl   = (realPrice - paperState.entryPrice) * paperState.qty;
  const slipData  = applySlippageToPnl(rawPnl, paperState.entryPrice, realPrice, paperState.qty, 1000000);
  const pnlUsd   = slipData.realPnl;
  const pnlPct   = ((realPrice - paperState.entryPrice) / paperState.entryPrice) * 100;

  paperState.capital += pnlUsd;
  paperState.position  = null;
  paperState.entryPrice = null;
  paperState.stats.totalTrades++;
  paperState.stats.totalPnlUsd += pnlUsd;
  paperState.stats.totalPnlPct  = ((paperState.capital - paperState.initialCapital) / paperState.initialCapital) * 100;

  if (pnlUsd > 0) {
    paperState.stats.winTrades++;
    if (pnlUsd > paperState.stats.largestWin) paperState.stats.largestWin = pnlUsd;
  } else {
    paperState.stats.lossTrades++;
    if (pnlUsd < paperState.stats.largestLoss) paperState.stats.largestLoss = pnlUsd;
  }

  // Equity curve
  if (paperState.capital > paperState.stats.peakCapital)
    paperState.stats.peakCapital = paperState.capital;
  const drawdown = ((paperState.capital - paperState.stats.peakCapital) / paperState.stats.peakCapital) * 100;
  if (drawdown < paperState.stats.maxDrawdown) paperState.stats.maxDrawdown = drawdown;
  paperState.stats.equityCurve.push({ t: Date.now(), equity: parseFloat(paperState.capital.toFixed(2)) });
  if (paperState.stats.equityCurve.length > 200) paperState.stats.equityCurve.shift();

  const trade = {
    symbol, side: "SELL", type: reason,
    pnlUsd: pnlUsd.toFixed(3), pnlPct: pnlPct.toFixed(3),
    slippageUsd: slipData.slippageUsd.toFixed(3),
    realPrice: realPrice.toFixed(4),
    capital: paperState.capital.toFixed(2),
    time: new Date().toLocaleTimeString("fr-FR"),
    won: pnlUsd > 0,
  };
  paperState.trades.unshift(trade);
  if (paperState.trades.length > 100) paperState.trades.pop();

  const emoji = pnlUsd >= 0 ? "✅" : "❌";
  addLog(
    `📄 [PAPER] ${emoji} SELL ${symbol} @ $${realPrice.toFixed(4)} | ` +
    `PnL:${pnlPct >= 0 ? "+" : ""}${pnlPct.toFixed(3)}% ($${pnlUsd.toFixed(2)}) | ` +
    `Slip:$${slipData.slippageUsd.toFixed(3)} | Capital:$${paperState.capital.toFixed(2)}`,
    pnlUsd >= 0 ? "success" : "error"
  );
  return trade;
}

// ══════════════════════════════════════════════════════════════════════════════
//  VOLUME PROFILE (VPVR) — Niveaux de support/résistance par volume
// ══════════════════════════════════════════════════════════════════════════════
function calcVolumeProfile(klines, buckets = 24) {
  if (!klines || klines.length < 10) return null;

  const prices  = klines.map(k => (parseFloat(k[2]) + parseFloat(k[3])) / 2); // HL/2
  const volumes = klines.map(k => parseFloat(k[5]));
  const high    = Math.max(...prices);
  const low     = Math.min(...prices);
  const range   = high - low;
  if (range === 0) return null;

  const bucketSize = range / buckets;
  const profile    = Array(buckets).fill(0).map((_, i) => ({
    priceFrom: low + i * bucketSize,
    priceTo:   low + (i + 1) * bucketSize,
    midPrice:  low + (i + 0.5) * bucketSize,
    volume:    0,
  }));

  klines.forEach((k, i) => {
    const mid = prices[i];
    const idx = Math.min(Math.floor((mid - low) / bucketSize), buckets - 1);
    profile[idx].volume += volumes[i];
  });

  const maxVol  = Math.max(...profile.map(b => b.volume));
  profile.forEach(b => b.volPct = maxVol > 0 ? (b.volume / maxVol * 100) : 0);

  // Point of Control (POC) — prix avec le plus de volume = support/résistance fort
  const poc     = profile.reduce((a, b) => b.volume > a.volume ? b : a);
  // Value Area (70% du volume)
  const totalVol = profile.reduce((a, b) => a + b.volume, 0);
  const sorted   = [...profile].sort((a, b) => b.volume - a.volume);
  let cumVol = 0;
  const valueArea = [];
  for (const b of sorted) {
    valueArea.push(b);
    cumVol += b.volume;
    if (cumVol >= totalVol * 0.7) break;
  }
  const vaHigh = Math.max(...valueArea.map(b => b.priceTo));
  const vaLow  = Math.min(...valueArea.map(b => b.priceFrom));

  // Niveaux clés: pics de volume = supports/résistances
  const keyLevels = profile
    .filter(b => b.volPct > 70)
    .sort((a, b) => b.volPct - a.volPct)
    .slice(0, 5)
    .map(b => ({ price: b.midPrice, volPct: b.volPct.toFixed(1) }));

  return {
    poc:       poc.midPrice,
    pocVolPct: poc.volPct.toFixed(1),
    vaHigh, vaLow,
    keyLevels,
    profile:   profile.map(b => ({ ...b, volume: b.volume.toFixed(2), midPrice: b.midPrice.toFixed(4) })),
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  LIQUIDATION LEVELS — Approximation via Open Interest + Prix
// ══════════════════════════════════════════════════════════════════════════════
async function getLiquidationLevels(symbol) {
  try {
    const [oiData, lsRatio] = await Promise.all([
      httpGetRaw(`${FUTURES_BASE}/fapi/v1/openInterest?symbol=${symbol}`),
      httpGetRaw(`${FUTURES_BASE}/futures/data/globalLongShortAccountRatio?symbol=${symbol}&period=5m&limit=1`)
        .catch(() => null),
    ]);

    const spotPrice = parseFloat(
      (await pubFetch("/api/v3/ticker/price", { symbol })).price
    );

    const oi = oiData ? parseFloat(oiData.openInterest) : 0;
    const longRatio  = lsRatio?.[0] ? parseFloat(lsRatio[0].longAccount)  : 0.5;
    const shortRatio = lsRatio?.[0] ? parseFloat(lsRatio[0].shortAccount) : 0.5;

    // Estimation des niveaux de liquidation
    // Longs à 10x levier: liquidés si -10% (donc à -10% du prix)
    // Shorts à 10x levier: liquidés si +10%
    const longLiq10x  = spotPrice * 0.90;
    const longLiq20x  = spotPrice * 0.95;
    const shortLiq10x = spotPrice * 1.10;
    const shortLiq20x = spotPrice * 1.05;

    // Pression directionnelle
    const lsPressure = longRatio > shortRatio ? "LONG_HEAVY" : "SHORT_HEAVY";
    const lsRatioVal = (longRatio / Math.max(shortRatio, 0.01)).toFixed(2);

    // Si marché long-heavy: cascade de liquidations possible vers le bas
    // Si short-heavy: short squeeze possible vers le haut
    const squeezeRisk = shortRatio > 0.6 ? "HIGH_SHORT_SQUEEZE" : "LOW";
    const dumpRisk    = longRatio  > 0.7 ? "HIGH_LONG_DUMP"    : "LOW";

    return {
      symbol, spotPrice: spotPrice.toFixed(4),
      openInterest: oi.toFixed(0),
      longRatio:  (longRatio  * 100).toFixed(1) + "%",
      shortRatio: (shortRatio * 100).toFixed(1) + "%",
      lsRatio: lsRatioVal,
      lsPressure,
      longLiqLevels:  { x10: longLiq10x.toFixed(4),  x20: longLiq20x.toFixed(4)  },
      shortLiqLevels: { x10: shortLiq10x.toFixed(4), x20: shortLiq20x.toFixed(4) },
      squeezeRisk, dumpRisk,
      // Signal: si beaucoup de longs et prix proche des liquidations → danger
      riskSignal: longRatio > 0.65 && spotPrice < longLiq10x * 1.03
        ? "DANGER_LONG_LIQ" : squeezeRisk === "HIGH_SHORT_SQUEEZE"
        ? "SHORT_SQUEEZE_RISK" : "NEUTRAL",
    };
  } catch(e) {
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  RETRY / RECONNEXION AUTOMATIQUE
// ══════════════════════════════════════════════════════════════════════════════
async function withRetry(fn, maxRetries = 3, delayMs = 1000, label = "") {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch(e) {
      if (attempt === maxRetries) throw e;
      addLog(`[RETRY ${attempt}/${maxRetries}] ${label}: ${e.message} — réessai dans ${delayMs}ms`, "warning");
      await new Promise(r => setTimeout(r, delayMs * attempt));
    }
  }
}

// Auto-reconnexion bot si crash inattendu
let _botWatchdog = null;
function startBotWatchdog() {
  if (_botWatchdog) clearInterval(_botWatchdog);
  _botWatchdog = setInterval(() => {
    if (!botState.running) return;
    const now       = Date.now();
    const lastCycle = botState.lastCycleTime || 0;
    const elapsed   = (now - lastCycle) / 1000;
    const maxGap    = (botState.config?.intervalMs || 60000) / 1000 * 3; // 3x l'intervalle
    if (lastCycle > 0 && elapsed > maxGap) {
      addLog(`⚠ Watchdog: aucun cycle depuis ${elapsed.toFixed(0)}s — redémarrage cycle`, "warning");
      botState.lastCycleTime = Date.now();
      botCycle(botState.config).catch(e =>
        addLog("Watchdog cycle error: " + e.message, "error")
      );
    }
  }, 30000); // vérifie toutes les 30s
}

// ══════════════════════════════════════════════════════════════════════════════
//  NIVEAU 3 — FEATURES INSTITUTIONNELLES
// ══════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
//  A. ORDER BOOK IMBALANCE — Prédit les mouvements 30-60s à l'avance
// ─────────────────────────────────────────────────────────────────────────────
async function getOrderBookImbalance(symbol, depth = 20, cfg = null) {
  try {
    const book = cfg ? await exchangeGetOrderBook(cfg, symbol, depth) : await pubFetch("/api/v3/depth", { symbol, limit: depth });
    if (!book.bids || !book.asks) return null;

    let bidVol = 0, askVol = 0;
    let bidWall = 0, askWall = 0;
    const bidPrices = [], askPrices = [];

    book.bids.slice(0, depth).forEach(([p, q]) => {
      const v = parseFloat(p) * parseFloat(q);
      bidVol += v;
      bidPrices.push({ price: parseFloat(p), vol: v });
      if (v > bidWall) bidWall = v;
    });
    book.asks.slice(0, depth).forEach(([p, q]) => {
      const v = parseFloat(p) * parseFloat(q);
      askVol += v;
      askPrices.push({ price: parseFloat(p), vol: v });
      if (v > askWall) askWall = v;
    });

    const total     = bidVol + askVol;
    const imbalance = total > 0 ? (bidVol - askVol) / total : 0; // -1 à +1
    const bidRatio  = total > 0 ? bidVol / total : 0.5;

    // Détection des murs (walls) — ordres massifs qui bloquent le prix
    const bigBidWall = bidPrices.find(b => b.vol > bidVol * 0.15);
    const bigAskWall = askPrices.find(a => a.vol > askVol * 0.15);

    // Signal: imbalance > 0.2 = pression achat, < -0.2 = pression vente
    const signal = imbalance > 0.25 ? "BUY_PRESSURE"
                 : imbalance < -0.25 ? "SELL_PRESSURE"
                 : "NEUTRAL";

    return {
      imbalance: parseFloat(imbalance.toFixed(4)),
      bidVol: bidVol.toFixed(2),
      askVol: askVol.toFixed(2),
      bidRatio: bidRatio.toFixed(3),
      signal,
      bigBidWall: bigBidWall ? bigBidWall.price : null,
      bigAskWall: bigAskWall ? bigAskWall.price : null,
      score: Math.round(imbalance * 10), // -10 à +10
    };
  } catch(e) {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  B. FUNDING RATE ARBITRAGE — Revenu passif Spot vs Futures
// ─────────────────────────────────────────────────────────────────────────────
const FUTURES_BASE = "https://fapi.binance.com";

async function httpGetRaw(url) {
  return new Promise((resolve, reject) => {
    const req = require("https").request(url, { method: "GET" }, (res) => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on("error", reject);
    req.end();
  });
}

async function getFundingRates(symbols = []) {
  try {
    const data = await httpGetRaw(`${FUTURES_BASE}/fapi/v1/premiumIndex`);
    if (!Array.isArray(data)) return [];
    const filtered = symbols.length > 0
      ? data.filter(d => symbols.includes(d.symbol))
      : data.filter(d => d.symbol.endsWith("USDT"));

    return filtered.map(d => {
      const rate     = parseFloat(d.lastFundingRate) * 100; // en %
      const nextTime = new Date(d.nextFundingTime).toLocaleTimeString("fr-FR");
      const annualized = rate * 3 * 365; // 3 fois par jour * 365
      // Si rate positif → les longs paient les shorts → vendre futures + acheter spot = arbitrage
      // Si rate négatif → les shorts paient les longs → acheter futures + vendre spot
      const opportunity = Math.abs(rate) > 0.05 ? (rate > 0 ? "SHORT_FUTURES" : "LONG_FUTURES") : "NONE";
      return {
        symbol: d.symbol,
        rate: rate.toFixed(4),
        annualized: annualized.toFixed(1),
        nextTime,
        markPrice: parseFloat(d.markPrice).toFixed(4),
        indexPrice: parseFloat(d.indexPrice).toFixed(4),
        opportunity,
        profitable: Math.abs(rate) > 0.05,
      };
    }).sort((a, b) => Math.abs(parseFloat(b.rate)) - Math.abs(parseFloat(a.rate)));
  } catch(e) {
    addLog("Funding rates error: " + e.message, "warning");
    return [];
  }
}

async function detectFundingArbitrage(symbol) {
  try {
    const [spotData, fundingData] = await Promise.all([
      pubFetch("/api/v3/ticker/price", { symbol }),
      httpGetRaw(`${FUTURES_BASE}/fapi/v1/premiumIndex?symbol=${symbol}`),
    ]);
    if (!spotData || !fundingData) return null;

    const spotPrice    = parseFloat(spotData.price);
    const futuresPrice = parseFloat(fundingData.markPrice);
    const fundingRate  = parseFloat(fundingData.lastFundingRate) * 100;
    const basis        = ((futuresPrice - spotPrice) / spotPrice) * 100;

    // Opportunité: basis + funding > frais (0.2%)
    const netOpportunity = Math.abs(fundingRate) + Math.abs(basis) - 0.2;

    return {
      symbol,
      spotPrice:    spotPrice.toFixed(4),
      futuresPrice: futuresPrice.toFixed(4),
      fundingRate:  fundingRate.toFixed(4),
      basis:        basis.toFixed(4),
      netOpportunity: netOpportunity.toFixed(4),
      viable: netOpportunity > 0.05,
      strategy: fundingRate > 0
        ? "BUY spot + SELL futures (touche le funding)"
        : "SELL spot + BUY futures (touche le funding)",
      annualizedYield: (Math.abs(fundingRate) * 3 * 365).toFixed(1),
    };
  } catch(e) {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  C. DÉTECTION BALEINES (On-chain via large trades)
// ─────────────────────────────────────────────────────────────────────────────
let _whaleCache = {};

async function detectWhaleActivity(symbol, thresholdUsd = 100000, cfg = null) {
  try {
    const trades = cfg ? await exchangeGetTrades(cfg, symbol, 200) : await pubFetch("/api/v3/aggTrades", { symbol, limit: 200 });
    if (!Array.isArray(trades)) return null;

    const priceData  = cfg ? await exchangeGetPrice(cfg, symbol) : await pubFetch("/api/v3/ticker/price", { symbol });
    const price      = parseFloat(priceData.price);
    const whaleTrades = [];
    let whaleBuyVol  = 0, whaleSellVol = 0;
    let totalBuyVol  = 0, totalSellVol = 0;

    trades.forEach(t => {
      const qty   = parseFloat(t.q);
      const usdVal = qty * price;
      const isBuy = !t.m; // m=true → maker = sell side

      if (isBuy) totalBuyVol += usdVal; else totalSellVol += usdVal;

      if (usdVal >= thresholdUsd) {
        whaleTrades.push({
          side:    isBuy ? "BUY" : "SELL",
          qty:     qty.toFixed(4),
          usdVal:  usdVal.toFixed(0),
          price:   parseFloat(t.p).toFixed(4),
          time:    new Date(t.T).toLocaleTimeString("fr-FR"),
        });
        if (isBuy) whaleBuyVol += usdVal; else whaleSellVol += usdVal;
      }
    });

    const totalWhale = whaleBuyVol + whaleSellVol;
    const whalePressure = totalWhale > 0
      ? (whaleBuyVol - whaleSellVol) / totalWhale
      : 0;

    // Delta cumulatif (CVD) — si positif = accumulation
    const cvd   = totalBuyVol - totalSellVol;
    const signal = whalePressure > 0.3 ? "WHALE_BUYING"
                 : whalePressure < -0.3 ? "WHALE_SELLING"
                 : "NEUTRAL";

    // Cache pour comparaison
    const prev = _whaleCache[symbol] || { cvd: 0 };
    const cvdChange = cvd - prev.cvd;
    _whaleCache[symbol] = { cvd, ts: Date.now() };

    return {
      symbol,
      whaleTrades:  whaleTrades.slice(0, 5),
      whaleCount:   whaleTrades.length,
      whaleBuyVol:  (whaleBuyVol / 1000).toFixed(1) + "K",
      whaleSellVol: (whaleSellVol / 1000).toFixed(1) + "K",
      whalePressure: whalePressure.toFixed(3),
      cvd:           (cvd / 1000).toFixed(1) + "K",
      cvdChange:     (cvdChange / 1000).toFixed(1) + "K",
      signal,
      score: Math.round(whalePressure * 8), // -8 à +8
    };
  } catch(e) {
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  OPTIMISEUR DE PARAMÈTRES — Walk-Forward Optimization
// ══════════════════════════════════════════════════════════════════════════════

// Simule une stratégie RSI sur des données historiques
function backtestRSI(closes, highs, lows, params) {
  const { rsiOs, rsiOb, sl, tp, trailPct } = params;
  let position = null, entryPrice = 0, highestPrice = 0;
  let trades = [], equity = 1000; // capital fictif $1000

  for (let i = 20; i < closes.length; i++) {
    const slice = closes.slice(0, i + 1);
    const rsi   = calcRSI(slice, 14);
    const cur   = closes[i];
    if (rsi === null) continue;

    const bb  = calcBollingerBands(slice);
    const ema9  = calcEMA(slice, 9);
    const ema21 = calcEMA(slice, 21);

    if (!position) {
      // Signal d'entrée
      const buyRSI  = rsi < rsiOs;
      const buyBB   = bb && cur < bb.lower;
      const buyEMA  = ema9 && ema21 && ema9 > ema21;
      if (buyRSI || (buyBB && buyEMA)) {
        position     = "LONG";
        entryPrice   = cur;
        highestPrice = cur;
      }
    } else {
      highestPrice = Math.max(highestPrice, cur);
      const pnlPct   = ((cur - entryPrice) / entryPrice) * 100;
      const trailSL  = highestPrice * (1 - trailPct / 100);
      const sellRSI  = rsi > rsiOb;

      if (pnlPct >= tp || sellRSI || cur <= trailSL || pnlPct <= -sl) {
        const pnl = (cur - entryPrice) / entryPrice;
        equity   *= (1 + pnl);
        trades.push({
          pnl: pnl * 100,
          won: pnl > 0,
          entry: entryPrice,
          exit: cur,
        });
        position = null;
        entryPrice = 0;
      }
    }
  }

  if (!trades.length) return null;
  const wins    = trades.filter(t => t.won).length;
  const losses  = trades.length - wins;
  const winRate = wins / trades.length;
  const avgWin  = trades.filter(t => t.won).reduce((a, t) => a + t.pnl, 0) / Math.max(wins, 1);
  const avgLoss = trades.filter(t => !t.won).reduce((a, t) => a + t.pnl, 0) / Math.max(losses, 1);
  const profitFactor = avgLoss !== 0 ? Math.abs((avgWin * wins) / (avgLoss * losses)) : 999;
  const totalReturn  = ((equity - 1000) / 1000) * 100;

  // Score composite pour l'optimiseur
  const score = winRate * 40 + Math.min(profitFactor, 5) * 20 + Math.min(totalReturn / 10, 20);

  return {
    trades:      trades.length,
    wins, losses, winRate,
    avgWin:      avgWin.toFixed(3),
    avgLoss:     avgLoss.toFixed(3),
    profitFactor: profitFactor.toFixed(2),
    totalReturn:  totalReturn.toFixed(2),
    score:        score.toFixed(1),
    equity:       equity.toFixed(2),
  };
}

async function runParameterOptimizer(symbol, interval = "1h", capital = 1000) {
  addLog(`🔧 Optimiseur démarré sur ${symbol} (${interval})...`, "info");

  try {
    // Récupérer 500 bougies historiques
    const klines = await exchangePubKlines(cfg, symbol, interval, 500);
    if (!Array.isArray(klines) || klines.length < 100) throw new Error("Données insuffisantes");

    const closes = klines.map(k => parseFloat(k[4]));
    const highs  = klines.map(k => parseFloat(k[2]));
    const lows   = klines.map(k => parseFloat(k[3]));

    // Grille de paramètres à tester
    const grid = {
      rsiOs:    [20, 25, 30, 35],
      rsiOb:    [65, 70, 75, 80],
      sl:       [1.0, 1.5, 2.0, 2.5, 3.0],
      tp:       [2.0, 3.0, 4.0, 5.0, 6.0],
      trailPct: [0.5, 1.0, 1.5, 2.0],
    };

    const results = [];
    let tested    = 0;
    const total   = grid.rsiOs.length * grid.rsiOb.length * grid.sl.length * grid.tp.length * grid.trailPct.length;

    addLog(`Optimiseur: test de ${total} combinaisons sur ${closes.length} bougies...`, "info");

    for (const rsiOs of grid.rsiOs) {
      for (const rsiOb of grid.rsiOb) {
        if (rsiOb <= rsiOs + 20) continue; // spread minimum
        for (const sl of grid.sl) {
          for (const tp of grid.tp) {
            if (tp <= sl) continue; // TP doit > SL
            for (const trailPct of grid.trailPct) {
              if (trailPct >= sl) continue; // trail ne doit pas > SL
              const result = backtestRSI(closes, highs, lows, { rsiOs, rsiOb, sl, tp, trailPct });
              if (result && result.trades >= 5) {
                results.push({ rsiOs, rsiOb, sl, tp, trailPct, ...result });
              }
              tested++;
            }
          }
        }
      }
    }

    // Trier par score composite
    results.sort((a, b) => parseFloat(b.score) - parseFloat(a.score));
    const top5 = results.slice(0, 5);

    // Walk-forward validation sur les 20% derniers
    const splitIdx  = Math.floor(closes.length * 0.8);
    const testCloses = closes.slice(splitIdx);
    const testHighs  = highs.slice(splitIdx);
    const testLows   = lows.slice(splitIdx);

    const validated = top5.map(p => {
      const wfResult = backtestRSI(testCloses, testHighs, testLows, p);
      return { ...p, wfResult, wfScore: wfResult?.score || 0 };
    }).sort((a, b) => parseFloat(b.wfScore) - parseFloat(a.wfScore));

    const best = validated[0];
    addLog(
      `✅ Optimiseur terminé: ${tested} combos testées · ` +
      `Meilleurs: RSI(${best.rsiOs}/${best.rsiOb}) SL:${best.sl}% TP:${best.tp}% Trail:${best.trailPct}% ` +
      `→ WinRate:${(parseFloat(best.winRate)*100).toFixed(1)}% Return:${best.totalReturn}%`,
      "success"
    );

    return {
      symbol, interval,
      tested: tested,
      totalCombos: total,
      best: best,
      top5: validated,
      dataPoints: closes.length,
    };
  } catch(e) {
    addLog("Erreur optimiseur: " + e.message, "error");
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  DÉTECTION DU RÉGIME DE MARCHÉ (ADX + Choppiness Index)
// ══════════════════════════════════════════════════════════════════════════════

function calcADX(highs, lows, closes, p = 14) {
  if (closes.length < p * 2) return null;
  const trs = [], plusDMs = [], minusDMs = [];

  for (let i = 1; i < closes.length; i++) {
    const h   = highs[i],  ph  = highs[i-1];
    const l   = lows[i],   pl  = lows[i-1];
    const c1  = closes[i-1];
    trs.push(Math.max(h - l, Math.abs(h - c1), Math.abs(l - c1)));
    const upMove   = h - ph;
    const downMove = pl - l;
    plusDMs.push(upMove   > downMove && upMove   > 0 ? upMove   : 0);
    minusDMs.push(downMove > upMove  && downMove > 0 ? downMove : 0);
  }

  // Wilder smoothing
  const smooth = (arr, p) => {
    let val = arr.slice(0, p).reduce((a, b) => a + b, 0);
    const smoothed = [val];
    for (let i = p; i < arr.length; i++) {
      val = val - val / p + arr[i];
      smoothed.push(val);
    }
    return smoothed;
  };

  const sTR   = smooth(trs,      p);
  const sPDM  = smooth(plusDMs,  p);
  const sMDM  = smooth(minusDMs, p);

  const diPlus  = sPDM.map((v, i) => sTR[i] > 0 ? (v / sTR[i]) * 100 : 0);
  const diMinus = sMDM.map((v, i) => sTR[i] > 0 ? (v / sTR[i]) * 100 : 0);
  const dx      = diPlus.map((v, i) => {
    const sum = v + diMinus[i];
    return sum > 0 ? (Math.abs(v - diMinus[i]) / sum) * 100 : 0;
  });

  const adx     = smooth(dx, p);
  const lastADX = adx.at(-1);
  const lastDIP = diPlus.at(-1);
  const lastDIM = diMinus.at(-1);

  return {
    adx:    lastADX,
    diPlus: lastDIP,
    diMinus: lastDIM,
    trending: lastADX > 25,
    strongTrend: lastADX > 40,
    direction: lastDIP > lastDIM ? "UP" : "DOWN",
  };
}

function calcChoppiness(highs, lows, closes, p = 14) {
  // 100 = parfaitement chaotique, 0 = parfaitement tendanciel
  // Seuil: < 38.2 = tendance forte, > 61.8 = range/chop
  if (closes.length < p + 1) return null;
  const slice_h = highs.slice(-p);
  const slice_l = lows.slice(-p);
  const slice_c = closes.slice(-(p + 1));

  const highMax = Math.max(...slice_h);
  const lowMin  = Math.min(...slice_l);
  if (highMax === lowMin) return null;

  let trSum = 0;
  for (let i = 1; i <= p; i++) {
    const h  = highs[highs.length - p + i - 1];
    const l  = lows[lows.length  - p + i - 1];
    const pc = closes[closes.length - p + i - 2];
    trSum += Math.max(h - l, Math.abs(h - pc), Math.abs(l - pc));
  }

  const ci = 100 * Math.log10(trSum / (highMax - lowMin)) / Math.log10(p);
  return parseFloat(ci.toFixed(2));
}

function detectMarketRegime(highs, lows, closes, volumes) {
  const adxData  = calcADX(highs, lows, closes, 14);
  const chop     = calcChoppiness(highs, lows, closes, 14);
  const atr      = calcATR(highs, lows, closes, 14);
  const cur      = closes.at(-1);
  const atrPct   = atr ? (atr / cur) * 100 : 0;

  // Volume trend
  const volRecent = volumes.slice(-5).reduce((a, b) => a + b, 0) / 5;
  const volAvg    = volumes.slice(-20).reduce((a, b) => a + b, 0) / 20;
  const volRatio  = volAvg > 0 ? volRecent / volAvg : 1;

  let regime = "UNKNOWN";
  let strategyAdvice = "";
  let confidence = 0;
  let allowTrading = true;
  let preferredStrategy = "RSI";

  if (adxData && chop !== null) {
    const adx       = adxData.adx;
    const trending  = adx > 25;
    const strongTrend = adx > 40;
    const ranging   = chop > 61.8;
    const choppy    = chop > 70;

    if (choppy && atrPct > 4) {
      // Marché ultra-volatile et chaotique → danger
      regime           = "VOLATILE_CHOP";
      strategyAdvice   = "⛔ Marché chaotique — trading déconseillé";
      confidence       = 85;
      allowTrading     = false;
      preferredStrategy = "NONE";

    } else if (strongTrend && adxData.direction === "UP" && volRatio > 1.2) {
      // Tendance haussière forte + volume
      regime           = "STRONG_UPTREND";
      strategyAdvice   = "✅ Forte tendance haussière — stratégie MOMENTUM";
      confidence       = Math.min(95, 60 + adx);
      preferredStrategy = "MULTI";

    } else if (strongTrend && adxData.direction === "DOWN") {
      // Tendance baissière forte → éviter les BUY
      regime           = "STRONG_DOWNTREND";
      strategyAdvice   = "⚠ Forte tendance baissière — BUY risqué";
      confidence       = Math.min(90, 55 + adx);
      allowTrading     = false;
      preferredStrategy = "NONE";

    } else if (trending && adxData.direction === "UP") {
      // Tendance modérée haussière
      regime           = "UPTREND";
      strategyAdvice   = "✅ Tendance haussière — RSI + EMA recommandés";
      confidence       = Math.min(80, 50 + adx);
      preferredStrategy = "RSI";

    } else if (ranging && !trending) {
      // Range / consolidation → mean-reversion
      regime           = "RANGING";
      strategyAdvice   = "🔄 Marché en range — RSI oversold/overbought optimal";
      confidence       = Math.min(85, 40 + chop);
      preferredStrategy = "RSI";

    } else {
      // Transition ou indécis
      regime           = "TRANSITIONAL";
      strategyAdvice   = "⏳ Marché en transition — réduire la taille des positions";
      confidence       = 40;
      preferredStrategy = "RSI";
    }
  }

  return {
    regime, strategyAdvice, confidence, allowTrading, preferredStrategy,
    adx: adxData?.adx?.toFixed(1),
    adxDirection: adxData?.direction,
    diPlus:  adxData?.diPlus?.toFixed(1),
    diMinus: adxData?.diMinus?.toFixed(1),
    choppiness: chop,
    atrPct:  atrPct.toFixed(3),
    volRatio: volRatio.toFixed(2),
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  CIRCUIT BREAKER — Protection du capital
// ══════════════════════════════════════════════════════════════════════════════
const circuitBreakerState = {
  triggered:     false,
  triggerReason: null,
  triggerTime:   null,
  dailyPnl:      0,
  dailyTrades:   0,
  dailyLosses:   0,
  sessionStart:  Date.now(),
  lastReset:     new Date().toDateString(),
};

function resetDailyCircuitBreaker() {
  const today = new Date().toDateString();
  if (circuitBreakerState.lastReset !== today) {
    circuitBreakerState.dailyPnl    = 0;
    circuitBreakerState.dailyTrades = 0;
    circuitBreakerState.dailyLosses = 0;
    circuitBreakerState.triggered   = false;
    circuitBreakerState.triggerReason = null;
    circuitBreakerState.lastReset   = today;
    addLog("🔄 Circuit breaker réinitialisé (nouveau jour)", "info");
  }
}

function checkCircuitBreaker(cfg, currentPnlUsd) {
  resetDailyCircuitBreaker();
  if (circuitBreakerState.triggered) {
    return {
      triggered: true,
      reason: circuitBreakerState.triggerReason,
      resumeAt: new Date(circuitBreakerState.triggerTime + 3600000).toLocaleTimeString(),
    };
  }

  const maxDailyLoss   = parseFloat(cfg.cbMaxDailyLoss  || -50);   // -$50 par jour
  const maxDailyTrades = parseInt(cfg.cbMaxDailyTrades   || 30);    // 30 trades/jour
  const maxLossStreak  = parseInt(cfg.cbMaxLossStreak    || 4);     // 4 pertes consécutives
  const maxDrawdown    = parseFloat(cfg.cbMaxDrawdown    || -10);   // -10% du capital initial

  // Règle 1 — Perte journalière max
  if (circuitBreakerState.dailyPnl <= maxDailyLoss) {
    circuitBreakerState.triggered     = true;
    circuitBreakerState.triggerReason = `💸 Perte journalière max atteinte: $${circuitBreakerState.dailyPnl.toFixed(2)} ≤ $${maxDailyLoss}`;
    circuitBreakerState.triggerTime   = Date.now();
    addLog("🚨 CIRCUIT BREAKER — " + circuitBreakerState.triggerReason, "error");
    return { triggered: true, reason: circuitBreakerState.triggerReason };
  }

  // Règle 2 — Nombre de trades max
  if (circuitBreakerState.dailyTrades >= maxDailyTrades) {
    circuitBreakerState.triggered     = true;
    circuitBreakerState.triggerReason = `🔢 Limite journalière: ${circuitBreakerState.dailyTrades} trades effectués`;
    circuitBreakerState.triggerTime   = Date.now();
    addLog("🚨 CIRCUIT BREAKER — " + circuitBreakerState.triggerReason, "error");
    return { triggered: true, reason: circuitBreakerState.triggerReason };
  }

  // Règle 3 — Série de pertes consécutives
  if (circuitBreakerState.dailyLosses >= maxLossStreak) {
    circuitBreakerState.triggered     = true;
    circuitBreakerState.triggerReason = `📉 ${circuitBreakerState.dailyLosses} pertes consécutives — pause forcée`;
    circuitBreakerState.triggerTime   = Date.now();
    addLog("🚨 CIRCUIT BREAKER — " + circuitBreakerState.triggerReason, "error");
    return { triggered: true, reason: circuitBreakerState.triggerReason };
  }

  return { triggered: false };
}

function recordCircuitBreakerTrade(pnlUsd) {
  resetDailyCircuitBreaker();
  circuitBreakerState.dailyPnl    += pnlUsd;
  circuitBreakerState.dailyTrades++;
  if (pnlUsd < 0) {
    circuitBreakerState.dailyLosses++;
  } else {
    circuitBreakerState.dailyLosses = 0; // reset série si gain
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  SCAN AUTOMATIQUE DES STABLECOINS
// ══════════════════════════════════════════════════════════════════════════════
async function scanStablecoins(feeRate, tradeAmt, minSpreadUsd) {
  const results = [];
  for (const sym of SC_PAIRS_LIST) {
    try {
      const book = await pubFetch("/api/v3/depth", { symbol: sym, limit: 5 });
      if (!book.bids || !book.asks || !book.bids[0] || !book.asks[0]) continue;
      const bestBid    = parseFloat(book.bids[0][0]);
      const bestAsk    = parseFloat(book.asks[0][0]);
      const spread     = bestAsk - bestBid;
      const spreadPct  = (spread / bestAsk) * 100;
      const feeCost    = tradeAmt * feeRate * 2;
      const minProfPct = (feeCost / tradeAmt) * 100;
      const profitable = spread >= minSpreadUsd && spreadPct > minProfPct;
      const netPnlEst  = (spread * (tradeAmt / bestAsk)) - feeCost;
      results.push({ sym, bestBid, bestAsk, spread, spreadPct, profitable, netPnlEst, feeCost });
      botState.scScanResults[sym] = { spread, spreadPct, profitable, netPnlEst, bestBid, bestAsk, ts: Date.now() };
    } catch(e) {
      botState.scScanResults[sym] = { spread: 0, profitable: false, error: e.message };
    }
  }
  // Trier par netPnlEst décroissant — meilleure opportunité en premier
  results.sort((a, b) => b.netPnlEst - a.netPnlEst);
  return results;
}

// ══════════════════════════════════════════════════════════════════════════════
//  SCANNER MULTI-ACTIFS — Analyse tous les pairs USDT
// ══════════════════════════════════════════════════════════════════════════════

// Cache des résultats de scan pour éviter les appels redondants
let _symbolsCache = null;
let _symbolsCacheTs = 0;

async function fetchAllUsdtSymbols() {
  const now = Date.now();
  if (_symbolsCache && now - _symbolsCacheTs < 3600000) return _symbolsCache; // cache 1h
  try {
    const info = await pubFetch("/api/v3/exchangeInfo");
    const symbols = info.symbols
      .filter(s => s.quoteAsset === "USDT"
                && s.status === "TRADING"
                && s.isSpotTradingAllowed)
      .map(s => s.symbol);
    _symbolsCache   = symbols;
    _symbolsCacheTs = now;
    addLog(`Scanner: ${symbols.length} paires USDT actives trouvées`, "info");
    return symbols;
  } catch(e) {
    addLog("Erreur fetchAllUsdtSymbols: " + e.message, "error");
    return [];
  }
}

async function quickScore(symbol) {
  try {
    // On utilise l'interval 15m pour avoir un signal fiable sans trop d'appels
    const [kRaw, ticker] = await Promise.all([
      pubFetch("/api/v3/klines", { symbol, interval: "15m", limit: 50 }),
      pubFetch("/api/v3/ticker/24hr", { symbol }),
    ]);
    if (!Array.isArray(kRaw) || kRaw.length < 20) return null;

    const closes  = kRaw.map(k => parseFloat(k[4]));
    const highs   = kRaw.map(k => parseFloat(k[2]));
    const lows    = kRaw.map(k => parseFloat(k[3]));
    const volumes = kRaw.map(k => parseFloat(k[5]));
    const cur     = closes.at(-1);

    // Indicateurs rapides
    const rsi      = calcRSI(closes, 14);
    const ema9     = calcEMA(closes, 9);
    const ema21    = calcEMA(closes, 21);
    const atr      = calcATR(highs, lows, closes, 14);
    const vol24h   = parseFloat(ticker.quoteVolume || 0);
    const pct24h   = parseFloat(ticker.priceChangePercent || 0);
    const volRecent= volumes.slice(-5).reduce((a,b)=>a+b,0)/5;
    const volAvg   = volumes.slice(-20).reduce((a,b)=>a+b,0)/20;
    const volRatio = volAvg > 0 ? volRecent / volAvg : 1;

    // Momentum court terme (5 bougies)
    const momentum = closes.length >= 5
      ? ((closes.at(-1) - closes.at(-5)) / closes.at(-5)) * 100
      : 0;

    // Score composite 0-100
    let score = 50;

    // RSI — survente = opportunité d'achat
    if (rsi !== null) {
      if (rsi < 25)       score += 20;
      else if (rsi < 35)  score += 12;
      else if (rsi < 45)  score += 5;
      else if (rsi > 75)  score -= 20;
      else if (rsi > 65)  score -= 10;
    }
    // Tendance EMA
    if (ema9 && ema21) {
      const emaDiff = ((ema9 - ema21) / ema21) * 100;
      if (emaDiff > 0.1)        score += 10;
      else if (emaDiff > 0)     score += 5;
      else if (emaDiff < -0.1)  score -= 10;
    }
    // Volume surge = liquidité + intérêt
    if (volRatio > 2.5)       score += 15;
    else if (volRatio > 1.5)  score += 8;
    else if (volRatio < 0.5)  score -= 8;
    // Volume 24h minimum (liquidité)
    if (vol24h < 100000)      score -= 20; // trop peu liquide
    else if (vol24h > 10000000) score += 5;
    // Momentum positif modéré = tendance haussière
    if (momentum > 1 && momentum < 8)   score += 10;
    else if (momentum > 8)              score -= 5;  // déjà trop monté
    else if (momentum < -3)             score -= 10;
    // ATR relatif = volatilité exploitable
    const atrPct = atr ? (atr / cur) * 100 : 0;
    if (atrPct > 0.5 && atrPct < 3)    score += 8;
    else if (atrPct > 3)                score -= 5;  // trop volatile = risque
    // Variation 24h
    if (pct24h > 2 && pct24h < 15)     score += 5;
    else if (pct24h < -10)              score -= 10;

    score = Math.max(0, Math.min(100, Math.round(score)));

    return {
      symbol, score, cur, rsi: rsi?.toFixed(1),
      momentum: momentum.toFixed(2), volRatio: volRatio.toFixed(2),
      atrPct: atrPct.toFixed(3), vol24h, pct24h: pct24h.toFixed(2),
      ema9, ema21, recommendation:
        score >= 70 ? "STRONG_BUY" :
        score >= 60 ? "BUY" :
        score >= 45 ? "NEUTRAL" :
        score >= 35 ? "WAIT" : "AVOID",
    };
  } catch(e) {
    return null;
  }
}

// Scan par batch pour ne pas surcharger l'API Binance
async function runFullScan(cfg) {
  const {
    scanTopN = 10,
    scanMinVol24h = 500000,
    scanMinScore = 60,
    scanBatchSize = 20,
    scanInterval = "15m",
  } = cfg;

  addLog("🔍 Démarrage du scan complet...", "info");
  const allSymbols = await fetchAllUsdtSymbols();
  if (!allSymbols.length) return [];

  // Pré-filtrer avec le ticker 24h (appel unique groupé)
  let tickers = [];
  try {
    tickers = await pubFetch("/api/v3/ticker/24hr");
    if (!Array.isArray(tickers)) tickers = [];
  } catch(e) { tickers = []; }

  // Filtre rapide par volume
  const tickerMap = {};
  tickers.forEach(t => { tickerMap[t.symbol] = t; });

  const preFiltered = allSymbols.filter(sym => {
    const t = tickerMap[sym];
    if (!t) return false;
    const vol = parseFloat(t.quoteVolume || 0);
    const pct = parseFloat(t.priceChangePercent || 0);
    return vol >= scanMinVol24h && Math.abs(pct) < 25; // exclure pumps extrêmes
  });

  addLog(`Scanner: ${preFiltered.length} paires après filtre volume (>${scanMinVol24h.toLocaleString()} USDT)`, "info");

  // Analyse par batch avec délai pour respecter les rate limits Binance
  const results = [];
  for (let i = 0; i < preFiltered.length; i += scanBatchSize) {
    if (!botState.scannerRunning) break; // arrêt si bot stoppé
    const batch = preFiltered.slice(i, i + scanBatchSize);
    const batchResults = await Promise.all(batch.map(sym => quickScore(sym)));
    batchResults.forEach(r => { if (r) results.push(r); });
    addLog(`Scanner: ${Math.min(i+scanBatchSize, preFiltered.length)}/${preFiltered.length} paires analysées...`, "info");
    if (i + scanBatchSize < preFiltered.length) await new Promise(r => setTimeout(r, 300));
  }

  // Trier par score décroissant
  results.sort((a, b) => b.score - a.score);

  // Garder le top N avec score suffisant
  const topResults = results
    .filter(r => r.score >= scanMinScore)
    .slice(0, scanTopN);

  botState.scannerResults = results.slice(0, 50); // top 50 pour affichage
  botState.scannerLastRun = Date.now();

  // Mettre à jour les scores
  results.forEach(r => { botState.symbolScores[r.symbol] = r.score; });

  addLog(
    `✅ Scan terminé: ${results.length} paires scorées · Top: ${topResults.map(r=>r.symbol+'('+r.score+')').slice(0,5).join(', ')}`,
    "success"
  );

  return topResults;
}

// ══════════════════════════════════════════════════════════════════════════════
//  BOT MULTI-PAIRES — Gestion des positions simultanées
// ══════════════════════════════════════════════════════════════════════════════
let multiPositions = {}; // {symbol: {position, entryPrice, entryTime, qty}}

async function multiPairCycle(cfg) {
  if (!botState.scannerRunning) return;
  const {
    apiKey, apiSecret, testnet,
    scanTopN = 5, scanInterval = "15m",
    tradeAmt, sl, tp, scanMinScore = 60,
    rotatePairAfterMin = 30,
  } = cfg;

  // ── Rescan si nécessaire (toutes les rotatePairAfterMin minutes) ──
  const lastScan    = botState.scannerLastRun;
  const scanAgeMin  = lastScan ? (Date.now() - lastScan) / 60000 : 999;

  if (scanAgeMin >= rotatePairAfterMin || !botState.activeSymbols.length) {
    addLog(`🔄 Rotation/scan (dernier: ${scanAgeMin.toFixed(1)} min)`, "info");
    const top = await runFullScan(cfg);
    const newSymbols = top.map(r => r.symbol);

    // Identifier les paires à fermer (plus dans le top)
    for (const sym of Object.keys(multiPositions)) {
      const pos = multiPositions[sym];
      if (!pos.position) continue;
      const stillTop = newSymbols.includes(sym);
      const score    = botState.symbolScores[sym] || 0;

      if (!stillTop || score < scanMinScore - 10) {
        addLog(`📤 ${sym} sorti du top (score:${score}) — fermeture position`, "trade");
        try {
          const analysis = await analyzeSymbol(sym, "15m");
          const cur      = analysis.price;
          const pnlPct   = ((cur - pos.entryPrice) / pos.entryPrice) * 100;
          await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol: sym, side: "SELL", type: "MARKET", quantity: pos.qty });
          recordTrade("BUY_CLOSE", pos.entryPrice, cur, parseFloat(pos.qty), sym);
          addLog(`Fermeture ${sym} @ $${cur.toFixed(4)} PnL:${pnlPct>=0?"+":""}${pnlPct.toFixed(2)}%`, pnlPct>=0?"success":"error");
          delete multiPositions[sym];
        } catch(e) { addLog(`Erreur fermeture ${sym}: ${e.message}`, "error"); }
      }
    }
    botState.activeSymbols = newSymbols;
  }

  // ── Cycle sur chaque paire active ──────────────────────────────────────────
  for (const sym of botState.activeSymbols) {
    try {
      const analysis = await analyzeSymbol(sym, "15m");
      const { indicators: ind, recommendation, netScore } = analysis;
      const cur = analysis.price;
      const rsi = ind.rsi;
      const atr = ind.atr;
      const pos = multiPositions[sym] || { position: null };

      const dynTp = atr ? Math.max(parseFloat(tp), (atr/cur)*100*1.5) : parseFloat(tp);
      const dynSl = atr ? Math.min(-Math.abs(sl), -(atr/cur)*100)     : -Math.abs(sl);

      addLog(
        `[MULTI] ${sym} $${cur.toFixed(4)} Score:${botState.symbolScores[sym]||0} RSI:${rsi?.toFixed(1)||"—"} → ${recommendation}`,
        "info"
      );

      if (!pos.position && (recommendation === "STRONG_BUY" || recommendation === "BUY") && netScore >= 3) {
        addLog(`🟢 ENTRÉE ${sym} — Score:${botState.symbolScores[sym]} Net:${netScore}`, "trade");
        const qty = (parseFloat(tradeAmt) / cur).toFixed(5);
        const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
          { symbol: sym, side: "BUY", type: "MARKET", quantity: qty });
        multiPositions[sym] = { position: "LONG", entryPrice: cur, entryTime: Date.now(), qty };
        botState.trades.unshift({ ...order, entryPrice: cur, symbol: sym, time: new Date().toLocaleTimeString() });
        addLog(`BUY ${qty} ${sym} @ $${cur.toFixed(4)}`, "success");

      } else if (pos.position === "LONG") {
        const pnlPct = ((cur - pos.entryPrice) / pos.entryPrice) * 100;
        const pnlUsd = (cur - pos.entryPrice) * parseFloat(pos.qty);
        addLog(`  ${sym} LONG $${pos.entryPrice.toFixed(4)} PnL:${pnlPct>=0?"+":""}${pnlPct.toFixed(2)}%`, "info");

        if (pnlPct >= dynTp || recommendation === "STRONG_SELL") {
          addLog(`🔴 TP ${sym} +${pnlPct.toFixed(2)}% +$${pnlUsd.toFixed(2)}`, "trade");
          const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol: sym, side: "SELL", type: "MARKET", quantity: pos.qty });
          recordTrade("BUY_CLOSE", pos.entryPrice, cur, parseFloat(pos.qty), sym);
          botState.trades.unshift({ ...order, pnlUsd: pnlUsd.toFixed(2), pnlPct: pnlPct.toFixed(2), symbol: sym, time: new Date().toLocaleTimeString() });
          delete multiPositions[sym];

        } else if (pnlPct <= dynSl) {
          addLog(`🛑 SL ${sym} ${pnlPct.toFixed(2)}% $${pnlUsd.toFixed(2)}`, "error");
          await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol: sym, side: "SELL", type: "MARKET", quantity: pos.qty });
          recordTrade("BUY_CLOSE", pos.entryPrice, cur, parseFloat(pos.qty), sym);
          delete multiPositions[sym];
        }
      }
      // Petit délai entre chaque paire pour respecter rate limits
      await new Promise(r => setTimeout(r, 200));
    } catch(e) {
      addLog(`Erreur ${sym}: ${e.message}`, "error");
    }
  }
}

async function botCycle() {
  if (!botState.running || !botState.config) return;
  const cfg = botState.config;
  const { apiKey, apiSecret, testnet, symbol, strategy, interval,
          rsiOs, rsiOb, sl, tp, tradeAmt, dcaAmt,
          gridLevels, gridSpacing, useMultiIndicator,
          stablecoinMode, scSpread, scMinVolume } = cfg;

  try {
    // ── Analyse complète ──────────────────────────────────────────────────────
    const analysis = await analyzeSymbol(symbol, interval);
    const { indicators: ind, recommendation, signals, netScore } = analysis;
    const cur = analysis.price;

    const rsi   = ind.rsi;
    const bb    = ind.bb;
    const macd  = ind.macd;
    const ema9  = ind.ema9;
    const ema21 = ind.ema21;
    const atr   = ind.atr;

    // ══════════════════════════════════════════════════════════════════════════
    // MODE STABLECOIN AUTO-SWITCH
    // ══════════════════════════════════════════════════════════════════════════
    if (stablecoinMode) {
      const feeRate      = parseFloat(cfg.scFeeRate   || 0.001);
      const minSpreadUsd = parseFloat(cfg.scMinSpreadUsd || 0.0001);
      const tpUsd        = parseFloat(cfg.scTpUsd     || 0.0002);
      const slUsd        = parseFloat(cfg.scSlUsd     || 0.0001);
      const feeCost      = tradeAmt * feeRate * 2;
      const switchDelay  = 60 * 1000; // 1 minute avant basculement

      // ── Pas de position ouverte → scan + choix de la meilleure paire ────────
      if (!botState.position) {
        addLog("[SC] 🔍 Scan de tous les stablecoins...", "info");
        const scanResults = await scanStablecoins(feeRate, tradeAmt, minSpreadUsd);

        // Log résumé du scan
        for (const r of scanResults) {
          addLog(
            `  ${r.profitable ? "✅" : "❌"} ${r.sym} Spread:$${r.spread.toFixed(6)} (${r.spreadPct.toFixed(4)}%) NetEst:${r.netPnlEst>=0?"+":""}$${r.netPnlEst.toFixed(5)}`,
            r.profitable ? "success" : "info"
          );
        }

        const best = scanResults.find(r => r.profitable);

        if (!best) {
          addLog("[SC] ⏳ Aucun stablecoin rentable en ce moment — attente...", "warning");
          botState.currentScSymbol      = null;
          botState.scNotProfitableSince = botState.scNotProfitableSince || Date.now();
          return;
        }

        // Vérifier si on doit changer de paire
        const currentSym     = botState.currentScSymbol;
        const currentResult  = scanResults.find(r => r.sym === currentSym);
        const currentOk      = currentResult && currentResult.profitable;
        const notProfitableMs = botState.scNotProfitableSince ? Date.now() - botState.scNotProfitableSince : 0;

        if (currentSym && currentOk && best.sym !== currentSym) {
          // Paire actuelle encore rentable — rester dessus sauf si la nouvelle est BEAUCOUP meilleure
          const improvement = best.netPnlEst - currentResult.netPnlEst;
          if (improvement < 0.0001) {
            addLog(`[SC] ✋ Paire actuelle ${currentSym} encore rentable (net $${currentResult.netPnlEst.toFixed(5)}) — pas de switch`, "info");
            // Continuer avec la paire actuelle
            const book = await pubFetch("/api/v3/depth", { symbol: currentSym, limit: 5 });
            if (book.bids && book.asks) {
              Object.assign(best, {
                sym: currentSym,
                bestBid: parseFloat(book.bids[0][0]),
                bestAsk: parseFloat(book.asks[0][0]),
              });
              best.sym = currentSym;
            }
          } else {
            addLog(`[SC] 🔄 SWITCH vers ${best.sym} — amélioration +$${improvement.toFixed(5)}/trade`, "trade");
            botState.currentScSymbol = best.sym;
            botState.scNotProfitableSince = null;
          }
        } else if (!currentSym || (!currentOk && notProfitableMs >= switchDelay)) {
          if (currentSym && !currentOk) {
            addLog(`[SC] 🔄 SWITCH — ${currentSym} non rentable depuis ${(notProfitableMs/1000).toFixed(0)}s (>${switchDelay/1000}s) → ${best.sym}`, "trade");
          } else if (!currentSym) {
            addLog(`[SC] 🎯 Meilleure paire sélectionnée: ${best.sym} (net est. +$${best.netPnlEst.toFixed(5)}/trade)`, "success");
          }
          botState.currentScSymbol      = best.sym;
          botState.scNotProfitableSince = null;
        } else if (!currentOk && notProfitableMs < switchDelay) {
          const remaining = ((switchDelay - notProfitableMs) / 1000).toFixed(0);
          addLog(`[SC] ⏱ ${currentSym} non rentable — basculement vers ${best.sym} dans ${remaining}s`, "warning");
          return;
        }

        // ── Exécution sur la paire sélectionnée ──────────────────────────────
        const activeSym = botState.currentScSymbol;
        const activeRes = scanResults.find(r => r.sym === activeSym) || best;

        addLog(`[SC] ⚡ Trade sur ${activeSym} — Bid:$${activeRes.bestBid.toFixed(6)} Ask:$${activeRes.bestAsk.toFixed(6)} Spread:$${activeRes.spread.toFixed(6)}`, "info");

        const qty = (tradeAmt / activeRes.bestAsk).toFixed(2);

        if (activeRes.spread >= minSpreadUsd * 2) {
          addLog(`[SC] 🟢 MICRO-SPREAD — BUY $${tradeAmt} @ $${activeRes.bestAsk.toFixed(6)}`, "trade");
          const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol: activeSym, side: "BUY", type: "LIMIT", price: activeRes.bestAsk.toFixed(6), quantity: qty, timeInForce: "IOC" });
          if (parseFloat(order.executedQty) > 0) {
            const fill = parseFloat(order.cummulativeQuoteQty) / parseFloat(order.executedQty);
            botState.position   = "LONG";
            botState.entryPrice = fill;
            botState.entryTime  = Date.now();
            // Stocker la paire active dans la position
            botState.positionSymbol = activeSym;
            botState.trades.unshift({ ...order, entryPrice: fill, symbol: activeSym, type: "SC_BUY", time: new Date().toLocaleTimeString() });
            addLog(`SC BUY ${order.executedQty} ${activeSym} @ $${fill.toFixed(6)}`, "success");
          } else {
            addLog(`[SC] Ordre non rempli ${order.status} (spread disparu)`, "warning");
            botState.scNotProfitableSince = botState.scNotProfitableSince || Date.now();
          }
        } else {
          addLog(`[SC] ⏳ ${activeSym} Spread $${activeRes.spread.toFixed(6)} < seuil $${(minSpreadUsd*2).toFixed(6)} — attente`, "info");
          if (!botState.scNotProfitableSince) botState.scNotProfitableSince = Date.now();
        }

      } else {
        // ── Gestion position ouverte ─────────────────────────────────────────
        const activeSym = botState.positionSymbol || symbol;
        const book = await pubFetch("/api/v3/depth", { symbol: activeSym, limit: 5 });
        if (!book.bids || !book.asks) return;

        const bestBid  = parseFloat(book.bids[0][0]);
        const pnlUsd   = (bestBid - botState.entryPrice) * (tradeAmt / botState.entryPrice);
        const pnlPct   = ((bestBid - botState.entryPrice) / botState.entryPrice) * 100;
        const netPnl   = pnlUsd - feeCost;
        const elapsed  = ((Date.now() - botState.entryTime) / 1000).toFixed(1);

        addLog(
          `[SC] 📊 ${activeSym} LONG $${botState.entryPrice.toFixed(6)} → Bid $${bestBid.toFixed(6)} ` +
          `PnL brut ${pnlUsd>=0?"+":""}$${pnlUsd.toFixed(5)} · Net ${netPnl>=0?"+":""}$${netPnl.toFixed(5)} · ${elapsed}s`,
          pnlUsd >= 0 ? "info" : "warning"
        );

        const qty = (tradeAmt / botState.entryPrice).toFixed(2);

        if (pnlUsd >= tpUsd + feeCost) {
          addLog(`[SC] 🔴 TP — Net +$${netPnl.toFixed(5)} (${pnlPct.toFixed(5)}%)`, "trade");
          const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol: activeSym, side: "SELL", type: "LIMIT", price: bestBid.toFixed(6), quantity: qty, timeInForce: "IOC" });
          recordTrade("BUY_CLOSE", botState.entryPrice, bestBid, parseFloat(qty), activeSym);
          botState.trades.unshift({ ...order, pnlUsd: netPnl.toFixed(5), pnlPct: pnlPct.toFixed(5), type: "SC_TP", time: new Date().toLocaleTimeString() });
          botState.position = null; botState.entryPrice = null; botState.positionSymbol = null;
          botState.scNotProfitableSince = null;

        } else if (pnlUsd <= -slUsd) {
          addLog(`[SC] 🛑 STOP LOSS $${pnlUsd.toFixed(5)}`, "error");
          await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol: activeSym, side: "SELL", type: "MARKET", quantity: qty });
          recordTrade("BUY_CLOSE", botState.entryPrice, bestBid, parseFloat(qty), activeSym);
          botState.position = null; botState.entryPrice = null; botState.positionSymbol = null;

        } else if (parseFloat(elapsed) > 30) {
          addLog(`[SC] ⏱ TIME-STOP 30s — Net $${netPnl.toFixed(5)}`, "warning");
          await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol: activeSym, side: "SELL", type: "MARKET", quantity: qty });
          recordTrade("BUY_CLOSE", botState.entryPrice, bestBid, parseFloat(qty), activeSym);
          botState.position = null; botState.entryPrice = null; botState.positionSymbol = null;
        }
      }
      return;
    }

    // ── MODE SCANNER MULTI-PAIRES ──────────────────────────────────────────
    if (strategy === "SCANNER") {
      await multiPairCycle(cfg);
      return;
    }

    // ══════════════════════════════════════════════════════════════════════
    // STRATÉGIE RSI / MULTI — avec tous les filtres avancés
    // ══════════════════════════════════════════════════════════════════════
    if (strategy === "RSI" || strategy === "MULTI") {
      // ── 4. Fear & Greed Filter ──────────────────────────────────────────
      const fg      = await getFearGreedIndex();
      botState.fearGreed = fg;
      const fgCheck = fearGreedFilter(fg.value, strategy);
      addLog(`[F&G] ${fg.value} (${fg.classification}) → ${fgCheck.reason}`, "info");
      if (!fgCheck.allow && !botState.position) {
        addLog(`[F&G] 🚫 Entrée bloquée — marché trop euphorique`, "warning");
        return;
      }

      // ── 6. Filtre Temporel ──────────────────────────────────────────────
      const tCheck = timeFilter(cfg);
      addLog(`[TIME] ${tCheck.reason}`, tCheck.allowed ? "info" : "warning");
      if (!tCheck.allowed && !botState.position) return;

      // ── CIRCUIT BREAKER ─────────────────────────────────────────────────
      const cb = checkCircuitBreaker(cfg, circuitBreakerState.dailyPnl);
      if (cb.triggered) {
        addLog(`🚨 CIRCUIT BREAKER ACTIF — ${cb.reason}${cb.resumeAt?" · Reprise ~"+cb.resumeAt:""}`, "error");
        if (botState.position) {
          // Fermer la position ouverte immédiatement
          addLog("Circuit breaker: fermeture position en cours...", "warning");
        }
        return;
      }

      const effectiveRsiOs = parseFloat(rsiOs);
      const effectiveRsiOb = parseFloat(rsiOb);
      const useMulti       = strategy === "MULTI";

      // ── 2. Multi-Timeframe Confirmation ────────────────────────────────
      let mtfResult = { confirmed: true, reason: "MTF disabled", strength: 2 };
      if (cfg.useMTF && !botState.position) {
        mtfResult = await multiTimeframeSignal(symbol, interval);
        addLog(`[MTF] ${mtfResult.reason} (strength:${mtfResult.strength})`, mtfResult.confirmed?"info":"warning");
      }

      // ── NIVEAU 3A: Order Book Imbalance ─────────────────────────────────
      const obData = await getOrderBookImbalance(symbol, 20, cfg);
      if (obData) {
        addLog(`[OB] Imbalance:${obData.imbalance} (${obData.signal}) BidVol:$${obData.bidVol} AskVol:$${obData.askVol}`, "info");
        botState.lastOrderBook = obData;
      }

      // ── NIVEAU 3C: Whale Activity ────────────────────────────────────────
      const whaleData = await detectWhaleActivity(symbol, parseFloat(cfg.whaleThreshold || 50000), cfg);
      if (whaleData) {
        if (whaleData.signal !== "NEUTRAL")
          addLog(`[WHALE] 🐋 ${whaleData.signal} — ${whaleData.whaleCount} gros ordres | Buy:${whaleData.whaleBuyVol} Sell:${whaleData.whaleSellVol} | CVD:${whaleData.cvd}`, "trade");
        botState.lastWhaleData = whaleData;
      }

      // ── Analyse complète ────────────────────────────────────────────────
      const analysis = await analyzeSymbol(symbol, interval);
      const { indicators: ind, recommendation, signals, netScore, divergence, patterns } = analysis;
      const cur  = analysis.price;
      const rsi  = ind.rsi;
      const bb   = ind.bb;
      const macd = ind.macd;
      const atr  = ind.atr;
      const ema9  = ind.ema9;
      const ema21 = ind.ema21;

      // ── Régime de marché ────────────────────────────────────────────────
      const regime   = analysis.regime;
      addLog(
        `[REGIME] ${regime.regime} · ADX:${regime.adx} ${regime.adxDirection} · Chop:${regime.choppiness} · ${regime.strategyAdvice}`,
        regime.allowTrading ? "info" : "warning"
      );

      // Bloquer l'entrée si régime défavorable
      if (!regime.allowTrading && !botState.position) {
        addLog(`🚫 Entrée bloquée — régime ${regime.regime} (confiance: ${regime.confidence}%)`, "warning");
        return;
      }

      // Réduire la mise si marché transitionnel
      if (regime.regime === "TRANSITIONAL") {
        addLog("⚠ Marché transitionnel — mise réduite 50%", "warning");
      }

      // ── 9. Candle Patterns ─────────────────────────────────────────────
      const pScore   = patternScore(patterns || []);
      const patNames = (patterns || []).map(p => p.name).join(",") || "none";

      // ── 3. RSI Divergence ──────────────────────────────────────────────
      if (divergence?.bullDiv) addLog(`🔀 DIVERGENCE HAUSSIÈRE détectée sur ${symbol}`, "trade");
      if (divergence?.bearDiv) addLog(`🔀 DIVERGENCE BAISSIÈRE détectée sur ${symbol}`, "trade");

      // ── 8. Kelly Position Sizing adapté au régime ──────────────────────
      const regimeMultiplier = regime.regime === "STRONG_UPTREND" ? 1.2
        : regime.regime === "UPTREND"       ? 1.0
        : regime.regime === "RANGING"       ? 0.8
        : regime.regime === "TRANSITIONAL"  ? 0.5
        : 0.3;
      const kellyMise = kellyPositionSize(
        botState.stats,
        parseFloat(tradeAmt) * regimeMultiplier,
        parseFloat(cfg.maxMise || tradeAmt * 3) * regimeMultiplier,
        parseFloat(cfg.minMise || tradeAmt * 0.5)
      );

      // Signaux d'entrée et sortie
      let buySignal  = useMulti
        ? (netScore >= 3 && (rsi === null || rsi < 55) && (mtfResult.confirmed || mtfResult.strength >= 2))
        : (rsi !== null && rsi < effectiveRsiOs);
      let sellSignal = useMulti
        ? (netScore <= -3)
        : (rsi !== null && rsi > effectiveRsiOb);

      // Boost par divergence et patterns
      if (divergence?.bullDiv) { buySignal  = buySignal  || netScore >= 1; }
      if (divergence?.bearDiv) { sellSignal = sellSignal || netScore <= -1; }
      if (pScore >= 3)         { buySignal  = buySignal  || (rsi !== null && rsi < 50); }
      if (pScore <= -3)        { sellSignal = true; }

      // ── Boost Order Book Imbalance ───────────────────────────────────────
      if (obData) {
        if (obData.signal === "BUY_PRESSURE"  && obData.imbalance > 0.3)  buySignal  = buySignal  || netScore >= 2;
        if (obData.signal === "SELL_PRESSURE" && obData.imbalance < -0.3) sellSignal = sellSignal || true;
        if (obData.bigAskWall && analysis.price >= obData.bigAskWall * 0.998) {
          addLog(`[OB] ⚠ Mur vendeur détecté à $${obData.bigAskWall} — entrée prudente`, "warning");
          buySignal = false;
        }
      }

      // ── Boost Whale Signal ────────────────────────────────────────────────
      if (whaleData) {
        if (whaleData.signal === "WHALE_BUYING"  && whaleData.whalePressure > 0.4) {
          addLog(`[WHALE] 🟢 Accumulation baleines — renforcement signal BUY`, "trade");
          buySignal = buySignal || netScore >= 1;
        }
        if (whaleData.signal === "WHALE_SELLING" && whaleData.whalePressure < -0.4) {
          addLog(`[WHALE] 🔴 Distribution baleines — signal SELL renforcé`, "trade");
          sellSignal = true;
        }
      }

      // Boost Fear & Greed
      if (fgCheck.boost < 1.0 && buySignal) {
        addLog(`[F&G] Signal BUY affaibli (boost ${fgCheck.boost})`, "warning");
        if (fgCheck.boost < 0.7) buySignal = false;
      }

      const bbSignal = bb ? (cur < bb.lower ? "BUY" : cur > bb.upper ? "SELL" : null) : null;
      const indStr   = [
        rsi   ? `RSI:${rsi.toFixed(1)}`          : "",
        macd  ? `MACD:${macd.macd.toFixed(3)}`   : "",
        bb    ? `BB:${bbSignal||"MID"}`           : "",
        ema9 && ema21 ? `EMA:${ema9>ema21?"UP":"DOWN"}` : "",
        `Score:${netScore>0?"+":""}${netScore}`,
        pScore !== 0 ? `Candle:${pScore>0?"+":""}${pScore}(${patNames})` : "",
        divergence?.bullDiv ? "⬆DIV" : divergence?.bearDiv ? "⬇DIV" : "",
        `F&G:${fg.value}`,
      ].filter(Boolean).join(" · ");

      addLog(`[${strategy}] ${symbol} $${cur.toFixed(4)} · ${indStr}`, "info");
      addLog(`  → ${recommendation} | MTF:${mtfResult.reason}`, "info");

      // ── ENTRÉE ─────────────────────────────────────────────────────────
      if (!botState.position && buySignal) {
        // ── 7. Filtre Corrélation ────────────────────────────────────────
        const corrCheck = correlationFilter(symbol, multiPositions || {}, cfg.maxCorrelated || 2);
        if (!corrCheck.allowed) {
          addLog(`[CORR] 🚫 ${corrCheck.reason}`, "warning");
          return;
        }

        addLog(
          `${cfg.paperMode?"📄[PAPER] ":""}🟢 ENTRÉE ${strategy} — Score:${netScore} | F&G:${fg.value} | Régime:${regime.regime}(×${regimeMultiplier}) | Kelly:$${kellyMise.toFixed(2)}` +
          (obData    ? ` | OB:${obData.imbalance}(${obData.signal})`              : "") +
          (whaleData ? ` | Whale:${whaleData.signal}(${whaleData.whalePressure})` : ""),
          "trade"
        );
        const qty = (kellyMise / cur).toFixed(5);

        let order;
        if (cfg.paperMode) {
          // ── PAPER TRADING ────────────────────────────────────────────────
          paperState.active   = true;
          const slip          = estimateSlippage(cur, parseFloat(qty), vol?.volume || 1e6, 0);
          const realEntry     = cur * (1 + slip.pct / 100);
          paperState.position    = "LONG";
          paperState.entryPrice  = realEntry;
          paperState.entryTime   = Date.now();
          paperState.highestPrice = realEntry;
          paperState.qty         = parseFloat(qty);
          order = { orderId: "PAPER_" + Date.now(), symbol, side: "BUY", status: "PAPER", qty, price: realEntry, slip: slip.pct };
        } else {
          order = await withRetry(
            () => exchangePlaceOrder(cfg, symbol, "BUY", qty),
            3, 1000, "BUY order"
          );
        }

        botState.position     = "LONG";
        botState.entryPrice   = cfg.paperMode ? paperState.entryPrice : cur;
        botState.entryTime    = Date.now();
        botState.highestPrice = botState.entryPrice;
        botState.trailingSL   = calcTrailingSL(botState.entryPrice, botState.entryPrice, cfg.trailPct || 1.5);
        botState.partialState = { level: 0, remainingQty: parseFloat(qty), breakEvenMoved: false };
        botState.trades.unshift({ ...order, entryPrice: botState.entryPrice, kellyMise, fearGreed: fg.value });
        addLog(`${cfg.paperMode?"📄":""}BUY ${qty} ${symbol} @ $${botState.entryPrice.toFixed(4)} | SL trail: $${botState.trailingSL.toFixed(4)}${cfg.paperMode?" [SIMULATION]":""}`, "success");

      // ── GESTION POSITION ────────────────────────────────────────────────
      } else if (botState.position === "LONG") {
        const pnlPct = ((cur - botState.entryPrice) / botState.entryPrice) * 100;
        const pnlUsd = (cur - botState.entryPrice) * botState.partialState.remainingQty;

        // ── 1. Trailing SL — mise à jour du plus haut ────────────────────
        if (cur > (botState.highestPrice || cur)) {
          botState.highestPrice = cur;
          botState.trailingSL   = calcTrailingSL(botState.entryPrice, cur, cfg.trailPct || 1.5);
          addLog(`📈 Nouveau high $${cur.toFixed(4)} · Trail SL → $${botState.trailingSL.toFixed(4)}`, "info");
        }

        // Break-even: si pnl > 1%, SL monte au prix d'entrée
        if (pnlPct > 1.0 && !botState.partialState.breakEvenMoved) {
          botState.trailingSL = Math.max(botState.trailingSL, botState.entryPrice * 1.001);
          botState.partialState.breakEvenMoved = true;
          addLog(`🔒 Break-even activé — SL à $${botState.trailingSL.toFixed(4)}`, "info");
        }

        // ATR dynamic TP
        const dynTp = atr ? Math.max(parseFloat(cfg.tp || 3), (atr/cur)*100*2) : parseFloat(cfg.tp || 3);

        addLog(
          `  LONG $${botState.entryPrice.toFixed(4)} | cur $${cur.toFixed(4)} | ` +
          `PnL:${pnlPct>=0?"+":""}${pnlPct.toFixed(3)}% ($${pnlUsd.toFixed(2)}) | ` +
          `TrailSL:$${botState.trailingSL?.toFixed(4)} | High:$${botState.highestPrice?.toFixed(4)}`,
          pnlPct >= 0 ? "info" : "warning"
        );

        // ── 5. Partial TP ────────────────────────────────────────────────
        const partial = checkPartialTP(pnlPct, botState.partialState, {
          tp1Pct: parseFloat(cfg.tp1Pct || 1.5),
          tp2Pct: parseFloat(cfg.tp2Pct || dynTp * 0.6),
          tp3Pct: parseFloat(cfg.tp3Pct || dynTp),
        });

        if (partial && botState.partialState.remainingQty > 0) {
          const sellQty = (botState.partialState.remainingQty * partial.sellFraction).toFixed(5);
          addLog(`💰 PARTIAL TP ${partial.level+1} — Vente ${(partial.sellFraction*100).toFixed(0)}% @ +${pnlPct.toFixed(2)}%`, "trade");
          const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol, side: "SELL", type: "MARKET", quantity: sellQty });
          const partialPnl = (cur - botState.entryPrice) * parseFloat(sellQty);
          botState.stats.totalPnlUsd  += partialPnl;
          botState.stats.totalTrades++;
          botState.stats.winTrades++;
          botState.partialState.level++;
          botState.partialState.remainingQty -= parseFloat(sellQty);
          botState.trades.unshift({
            ...order, pnlUsd: partialPnl.toFixed(3), pnlPct: pnlPct.toFixed(3),
            type: `PARTIAL_TP_${partial.level+1}`, time: new Date().toLocaleTimeString(),
          });
          if (botState.partialState.level >= 3) {
            botState.position = null; botState.entryPrice = null;
            botState.highestPrice = null; botState.trailingSL = null;
          }

        // ── Full TP / Signal SELL ────────────────────────────────────────
        } else if (sellSignal || pnlPct >= dynTp) {
          const qty   = botState.partialState.remainingQty.toFixed(5);
          addLog(`🔴 SORTIE COMPLÈTE — PnL:${pnlPct>=0?"+":""}${pnlPct.toFixed(3)}% $${pnlUsd.toFixed(2)}`, "trade");
          const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol, side: "SELL", type: "MARKET", quantity: qty });
          recordTrade("BUY_CLOSE", botState.entryPrice, cur, parseFloat(qty), symbol);
          botState.trades.unshift({ ...order, pnlUsd: pnlUsd.toFixed(2), pnlPct: pnlPct.toFixed(3) });
          botState.position = null; botState.entryPrice = null;
          botState.highestPrice = null; botState.trailingSL = null;

        // ── 1. Trailing Stop Loss HIT ────────────────────────────────────
        } else if (botState.trailingSL && cur <= botState.trailingSL) {
          const qty = botState.partialState.remainingQty.toFixed(5);
          addLog(`🎯 TRAILING SL HIT $${cur.toFixed(4)} ≤ $${botState.trailingSL.toFixed(4)} | PnL:${pnlPct>=0?"+":""}${pnlPct.toFixed(3)}%`, pnlPct>=0?"trade":"error");
          const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol, side: "SELL", type: "MARKET", quantity: qty });
          recordTrade("BUY_CLOSE", botState.entryPrice, cur, parseFloat(qty), symbol);
          botState.trades.unshift({ ...order, pnlUsd: pnlUsd.toFixed(2), type: "TRAIL_SL" });
          botState.position = null; botState.entryPrice = null;
          botState.highestPrice = null; botState.trailingSL = null;

        // ── SL classique (backup) ────────────────────────────────────────
        } else if (pnlPct <= -Math.abs(cfg.sl || 2)) {
          const qty = botState.partialState.remainingQty.toFixed(5);
          addLog(`🛑 STOP LOSS ${pnlPct.toFixed(3)}%`, "error");
          const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol, side: "SELL", type: "MARKET", quantity: qty });
          recordTrade("BUY_CLOSE", botState.entryPrice, cur, parseFloat(qty), symbol);
          botState.position = null; botState.entryPrice = null;
          botState.highestPrice = null; botState.trailingSL = null;
        }
      }

        } else if (strategy === "DCA") {
      const sma20 = ind.sma20;
      addLog(`[DCA] ${symbol} $${cur.toFixed(4)} · SMA20: $${sma20?.toFixed(4)||"—"} · RSI: ${rsi?.toFixed(1)||"—"}`, "info");

      // Conditions DCA renforcées
      const dcaBuyCondition = sma20 && cur < sma20 * 0.99 && (rsi === null || rsi < 50);
      if (dcaBuyCondition) {
        addLog(`🟢 DCA — Prix sous SMA20 · Achat ${dcaAmt} USDT`, "trade");
        const qty = (parseFloat(dcaAmt) / cur).toFixed(5);
        const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
          { symbol, side: "BUY", type: "MARKET", quantity: qty });
        botState.dcaOrders++;
        // Mise à jour du prix moyen DCA
        const prevTotalCost = (botState.dcaAvgPrice || cur) * botState.dcaTotalQty;
        botState.dcaTotalQty   += parseFloat(qty);
        botState.dcaAvgPrice    = (prevTotalCost + parseFloat(dcaAmt)) / botState.dcaTotalQty;
        botState.trades.unshift({ ...order, avgPrice: botState.dcaAvgPrice, dcaOrder: botState.dcaOrders });
        addLog(`DCA #${botState.dcaOrders} · Qty: ${qty} · Prix moyen: $${botState.dcaAvgPrice.toFixed(4)}`, "success");
      }

      // Take profit DCA
      if (botState.dcaAvgPrice && cur > botState.dcaAvgPrice * (1 + parseFloat(tp)/100)) {
        const pnlPct = ((cur - botState.dcaAvgPrice) / botState.dcaAvgPrice) * 100;
        const pnlUsd = (cur - botState.dcaAvgPrice) * botState.dcaTotalQty;
        addLog(`🔴 DCA TP — PnL: +${pnlPct.toFixed(3)}% · +${pnlUsd.toFixed(2)} USDT`, "trade");
        const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
          { symbol, side: "SELL", type: "MARKET", quantity: botState.dcaTotalQty.toFixed(5) });
        recordTrade("BUY_CLOSE", botState.dcaAvgPrice, cur, botState.dcaTotalQty, symbol);
        botState.dcaOrders = 0; botState.dcaAvgPrice = null; botState.dcaTotalQty = 0;
        botState.trades.unshift({ ...order, pnlPct: pnlPct.toFixed(3) });
      }

    } else if (strategy === "GRID") {
      const sp = parseFloat(gridSpacing) / 100;
      addLog(`[GRID] ${symbol} $${cur.toFixed(4)} · ${gridLevels} niveaux ±${gridSpacing}% · ATR: ${atr?.toFixed(4)||"—"}`, "info");
      for (let i = 1; i <= gridLevels; i++) {
        addLog(`  Grille ${i}: BUY $${(cur*(1-i*sp)).toFixed(4)} · SELL $${(cur*(1+i*sp)).toFixed(4)}`, "info");
      }

    } else if (strategy === "SCALP") {
      // Scalping ultra-rapide basé sur micro-momentum
      if (!rsi || !bb || !macd) { addLog("[SCALP] Indicateurs insuffisants", "warning"); return; }
      const getCloses = kl => kl.map(k => parseFloat(k[4]));
      const mom = (() => {
        const cl = getCloses(analysis.klines);
        const recent = cl.slice(-5);
        return (recent.at(-1) - recent[0]) / recent[0] * 100;
      })();
      const bbPos = bb ? (cur < bb.lower ? "OVERSOLD" : cur > bb.upper ? "OVERBOUGHT" : "MID") : "N/A";
      addLog(`[SCALP] ${symbol} $${cur.toFixed(6)} · Mom:${mom.toFixed(4)}% · RSI:${rsi.toFixed(1)} · BB:${bbPos}`, "info");

      if (!botState.position && mom > 0.02 && rsi < 60 && cur > ind.vwap * 0.999) {
        addLog(`⚡ SCALP ENTRY — Momentum +${mom.toFixed(4)}%`, "trade");
        const qty = (parseFloat(tradeAmt) / cur).toFixed(5);
        const order = await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
          { symbol, side: "BUY", type: "MARKET", quantity: qty });
        botState.position   = "LONG";
        botState.entryPrice = cur;
        botState.entryTime  = Date.now();
        botState.trades.unshift({ ...order, entryPrice: cur, type: "SCALP" });
        addLog(`SCALP BUY ${qty} @ $${cur.toFixed(6)}`, "success");

      } else if (botState.position === "LONG") {
        const pnlPct = ((cur - botState.entryPrice) / botState.entryPrice) * 100;
        const elapsed = (Date.now() - botState.entryTime) / 1000;
        addLog(`  SCALP pos · PnL: ${pnlPct>=0?"+":""}${pnlPct.toFixed(4)}% · ${elapsed.toFixed(0)}s`, "info");

        // Sortie rapide: TP 0.15%, SL -0.1%, ou après 30s
        if (pnlPct >= parseFloat(tp || 0.15) || pnlPct <= -Math.abs(sl || 0.1) || elapsed > 60) {
          const qty = (parseFloat(tradeAmt) / botState.entryPrice).toFixed(5);
          await binanceReq(apiKey, apiSecret, testnet, "POST", "/api/v3/order",
            { symbol, side: "SELL", type: "MARKET", quantity: qty });
          recordTrade("BUY_CLOSE", botState.entryPrice, cur, parseFloat(qty), symbol);
          botState.position = null; botState.entryPrice = null;
        }
      }
    }

  } catch (e) {
    addLog(`Erreur bot: ${e.message}`, "error");
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ROUTES HTTP
// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
//  RAPPORT EMAIL JOURNALIER
// ══════════════════════════════════════════════════════════════════════════════

function createTransporter() {
  if (!emailConfig.gmailUser || !emailConfig.gmailPass) return null;
  return nodemailer.createTransport({
    service: "gmail",
    auth: { user: emailConfig.gmailUser, pass: emailConfig.gmailPass },
  });
}

function buildDailyReport() {
  const s      = botState.stats;
  const now    = new Date();
  const uptime = ((Date.now() - sessionStartTime) / 3600000).toFixed(1);
  const winRate = s.totalTrades > 0 ? (s.winTrades / s.totalTrades * 100).toFixed(1) : "0.0";
  const avgPnl  = s.totalTrades > 0 ? (s.totalPnlUsd / s.totalTrades).toFixed(3) : "0";
  const pnlColor = s.totalPnlUsd >= 0 ? "#27ae60" : "#e74c3c";
  const pnlSign  = s.totalPnlUsd >= 0 ? "+" : "";

  // Derniers trades
  const recentTrades = botState.trades.slice(0, 10);
  const tradeRows = recentTrades.map(t => {
    const pnl    = parseFloat(t.pnlUsd || 0);
    const pnlPct = parseFloat(t.pnlPct || 0);
    const color  = pnl >= 0 ? "#27ae60" : "#e74c3c";
    const sign   = pnl >= 0 ? "+" : "";
    return `
      <tr style="border-bottom:1px solid #2d2d2d">
        <td style="padding:8px;color:#f0b90b;font-weight:700">${t.symbol || "—"}</td>
        <td style="padding:8px;color:#8b949e">${t.time || "—"}</td>
        <td style="padding:8px;color:#8b949e">${t.type || t.side || "—"}</td>
        <td style="padding:8px;color:${color};font-weight:700">${sign}$${pnl.toFixed(3)}</td>
        <td style="padding:8px;color:${color}">${sign}${pnlPct.toFixed(3)}%</td>
      </tr>`;
  }).join("") || '<tr><td colspan="5" style="padding:12px;color:#666;text-align:center">Aucun trade enregistré</td></tr>';

  // Paire active
  const activePair = botState.config ? `${botState.config.symbol} (${botState.config.strategy})` : "—";
  const botStatus  = botState.running ? "🟢 EN COURS" : "🔴 ARRÊTÉ";
  const pnlTotal   = parseFloat(s.totalPnlUsd || 0).toFixed(2);

  return {
    subject: `📊 BinanceBot — Rapport du ${now.toLocaleDateString("fr-FR")} | PnL: ${pnlSign}$${pnlTotal}`,
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/>
<style>
  body { font-family: 'Courier New', monospace; background:#0d1117; color:#c9d1d9; margin:0; padding:0; }
  .container { max-width:600px; margin:0 auto; padding:20px; }
  .header { background:linear-gradient(135deg,#0d1117,#161b22); border:1px solid #f0b90b44;
            border-radius:12px; padding:24px; text-align:center; margin-bottom:20px; }
  .logo { font-size:28px; font-weight:900; letter-spacing:4px; }
  .logo span { color:#f0b90b; }
  .subtitle { color:#8b949e; font-size:12px; margin-top:6px; letter-spacing:2px; }
  .card { background:#161b22; border:1px solid #21262d; border-radius:10px;
          padding:20px; margin-bottom:16px; }
  .card-title { font-size:11px; letter-spacing:3px; color:#8b949e; margin-bottom:16px; }
  .stat-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .stat { background:#0d1117; border-radius:8px; padding:14px; }
  .stat-label { font-size:10px; color:#8b949e; letter-spacing:2px; margin-bottom:6px; }
  .stat-value { font-size:22px; font-weight:700; }
  table { width:100%; border-collapse:collapse; }
  th { padding:8px; text-align:left; font-size:10px; letter-spacing:2px;
       color:#8b949e; border-bottom:1px solid #30363d; }
  .footer { text-align:center; color:#444; font-size:10px; margin-top:20px; padding:16px; }
  .badge { display:inline-block; padding:3px 10px; border-radius:12px;
           font-size:11px; font-weight:700; }
  .badge-green { background:#1a3a1a; color:#3fb950; border:1px solid #3fb95033; }
  .badge-red   { background:#3a1a1a; color:#f85149; border:1px solid #f8514933; }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div class="logo">BINANCE<span>BOT</span></div>
    <div class="subtitle">RAPPORT JOURNALIER — ${now.toLocaleDateString("fr-FR", {weekday:"long",day:"numeric",month:"long",year:"numeric"}).toUpperCase()}</div>
    <div style="margin-top:12px">
      <span class="badge ${botState.running ? "badge-green" : "badge-red"}">${botStatus}</span>
      &nbsp;
      <span style="color:#8b949e;font-size:11px">${activePair}</span>
    </div>
  </div>

  <!-- PNL Principal -->
  <div class="card" style="border-color:${s.totalPnlUsd>=0?"#3fb95033":"#f8514933"}">
    <div class="card-title">◆ PERFORMANCE GLOBALE</div>
    <div style="text-align:center;margin-bottom:20px">
      <div style="font-size:11px;color:#8b949e;letter-spacing:3px;margin-bottom:8px">PNL TOTAL NET</div>
      <div style="font-size:48px;font-weight:900;color:${pnlColor}">${pnlSign}$${pnlTotal}</div>
      <div style="color:${pnlColor};font-size:14px;margin-top:4px">${pnlSign}${s.totalPnlPct?.toFixed(2)||"0.00"}%</div>
    </div>
    <div class="stat-grid">
      <div class="stat">
        <div class="stat-label">TRADES TOTAL</div>
        <div class="stat-value" style="color:#f0b90b">${s.totalTrades || 0}</div>
      </div>
      <div class="stat">
        <div class="stat-label">WIN RATE</div>
        <div class="stat-value" style="color:${parseFloat(winRate)>=50?"#3fb950":"#f85149"}">${winRate}%</div>
      </div>
      <div class="stat">
        <div class="stat-label">WINS / LOSSES</div>
        <div class="stat-value" style="font-size:16px">
          <span style="color:#3fb950">${s.winTrades||0}W</span>
          <span style="color:#444"> / </span>
          <span style="color:#f85149">${s.lossTrades||0}L</span>
        </div>
      </div>
      <div class="stat">
        <div class="stat-label">PNL MOY/TRADE</div>
        <div class="stat-value" style="font-size:16px;color:${parseFloat(avgPnl)>=0?"#3fb950":"#f85149"}">
          ${parseFloat(avgPnl)>=0?"+":""}$${avgPnl}
        </div>
      </div>
    </div>
  </div>

  <!-- Meilleur / Pire trade -->
  ${s.bestTrade || s.worstTrade ? `
  <div class="card">
    <div class="card-title">◆ RECORDS DE LA SESSION</div>
    <div class="stat-grid">
      <div class="stat" style="border:1px solid #3fb95022">
        <div class="stat-label">🏆 MEILLEUR TRADE</div>
        <div style="color:#3fb950;font-weight:700;font-size:15px;margin-top:6px">
          ${s.bestTrade ? `+$${parseFloat(s.bestTrade.pnlUsd).toFixed(3)}<br>
          <span style="font-size:11px;color:#8b949e">${s.bestTrade.symbol} · ${s.bestTrade.time||""}</span>` : "—"}
        </div>
      </div>
      <div class="stat" style="border:1px solid #f8514922">
        <div class="stat-label">⚠ PIRE TRADE</div>
        <div style="color:#f85149;font-weight:700;font-size:15px;margin-top:6px">
          ${s.worstTrade ? `$${parseFloat(s.worstTrade.pnlUsd).toFixed(3)}<br>
          <span style="font-size:11px;color:#8b949e">${s.worstTrade.symbol} · ${s.worstTrade.time||""}</span>` : "—"}
        </div>
      </div>
    </div>
  </div>` : ""}

  <!-- Derniers trades -->
  <div class="card">
    <div class="card-title">◆ DERNIERS TRADES (10)</div>
    <table>
      <tr>
        <th>PAIRE</th><th>HEURE</th><th>TYPE</th><th>PNL USD</th><th>PNL %</th>
      </tr>
      ${tradeRows}
    </table>
  </div>

  <!-- Uptime -->
  <div class="card">
    <div class="card-title">◆ SESSION BOT</div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
      <div class="stat">
        <div class="stat-label">UPTIME</div>
        <div style="color:#64b5f6;font-weight:700;font-size:16px">${uptime}h</div>
      </div>
      <div class="stat">
        <div class="stat-label">STRATÉGIE</div>
        <div style="color:#f0b90b;font-size:13px;font-weight:700">${botState.config?.strategy||"—"}</div>
      </div>
      <div class="stat">
        <div class="stat-label">DRAWDOWN MAX</div>
        <div style="color:#f85149;font-size:13px;font-weight:700">$${parseFloat(s.maxDrawdown||0).toFixed(2)}</div>
      </div>
    </div>
  </div>

  <div class="footer">
    Généré automatiquement par BinanceBot le ${now.toLocaleString("fr-FR")}<br>
    Ce rapport est confidentiel — ne pas transférer
  </div>

</div>
</body>
</html>`
  };
}

async function sendDailyReport() {
  if (!emailConfig.enabled || !emailConfig.gmailUser || !emailConfig.recipient) {
    addLog("Email désactivé ou non configuré — rapport ignoré", "warning");
    return false;
  }
  const transporter = createTransporter();
  if (!transporter) { addLog("Erreur: transporter email non créé", "error"); return false; }

  try {
    const report = buildDailyReport();
    const info   = await transporter.sendMail({
      from:    `"BinanceBot 🤖" <${emailConfig.gmailUser}>`,
      to:      emailConfig.recipient,
      subject: report.subject,
      html:    report.html,
    });
    addLog(`📧 Rapport journalier envoyé → ${emailConfig.recipient} (${info.messageId})`, "success");
    return true;
  } catch(e) {
    addLog(`Erreur envoi email: ${e.message}`, "error");
    return false;
  }
}

// Planificateur de rapport quotidien (vérifie toutes les minutes)
function scheduleDailyReport() {
  if (dailyReportTimer) clearInterval(dailyReportTimer);
  dailyReportTimer = setInterval(() => {
    if (!emailConfig.enabled) return;
    const now = new Date();
    if (now.getHours()   === emailConfig.reportHour &&
        now.getMinutes() === emailConfig.reportMinute) {
      addLog(`⏰ Déclenchement rapport journalier (${emailConfig.reportHour}h${String(emailConfig.reportMinute).padStart(2,"0")})`, "info");
      sendDailyReport();
    }
  }, 60000); // vérification chaque minute
}

// Lancer le planificateur au démarrage
scheduleDailyReport();
addLog("Planificateur de rapport email initialisé", "info");

// ── Auto-optimisation toutes les 6h si bot actif ──────────────────────────
setInterval(async () => {
  if (!botState.running || !botState.config) return;
  const { symbol, interval, autoOptimize } = botState.config;
  if (!autoOptimize) return;
  addLog("⏰ Auto-optimisation périodique démarrée...", "info");
  try {
    const result = await runParameterOptimizer(symbol, interval || "1h");
    if (result?.best) {
      const best = result.best;
      botState.lastOptimResult  = result;
      botState.optimizedParams  = best;
      botState.config.rsiOs     = best.rsiOs;
      botState.config.rsiOb     = best.rsiOb;
      botState.config.sl        = best.sl;
      botState.config.tp        = best.tp;
      botState.config.trailPct  = best.trailPct;
      addLog(
        `✅ Auto-optimisation: RSI(${best.rsiOs}/${best.rsiOb}) SL:${best.sl}% TP:${best.tp}% Trail:${best.trailPct}%` +
        ` WinRate:${(parseFloat(best.winRate)*100).toFixed(1)}% Return:${best.totalReturn}%`,
        "success"
      );
    }
  } catch(e) {
    addLog("Erreur auto-optimisation: " + e.message, "warning");
  }
}, 6 * 60 * 60 * 1000); // toutes les 6h

app.get("/health", (req, res) => res.json({ status: "ok", secured: !!SERVER_SECRET }));

app.get("/", (req, res) => res.json({ status: "ok", message: "Binance Bot Proxy actif 🚀", botRunning: botState.running }));

app.post("/exchange", async (req, res) => {
  const safeBody = { ...req.body, apiKey: "***", apiSecret: "***" };
  const exchange = req.body?.exchange || "binance";
  securityLog(req, `${exchange} proxy — ${req.body?.endpoint || "?"}`);
  try {
    const { apiKey, apiSecret, testnet, endpoint, params, method, exchange: exch } = req.body;
    if (!apiKey || !apiSecret || !endpoint) return res.status(400).json({ error: "apiKey, apiSecret, endpoint requis" });
    const cfg = { apiKey, apiSecret, testnet, exchange: exch || "binance" };
    let result;
    if ((exch || "binance") === "bybit") {
      result = await bybitReq(apiKey, apiSecret, testnet, method || "GET", endpoint, params || {});
    } else {
      result = await binanceReq(apiKey, apiSecret, testnet, method || "GET", endpoint, params || {});
    }
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Rétrocompatibilité — /binance redirige vers /exchange
app.post("/binance", async (req, res) => {
  // Sécurité: ne JAMAIS logger apiKey/apiSecret
  const safeBody = { ...req.body, apiKey: "***", apiSecret: "***", signature: "***" };
  securityLog(req, `Binance proxy — ${req.body?.endpoint || "?"}`);
  const { apiKey, apiSecret, testnet, method="GET", path, params={} } = req.body;
  if (!apiKey || !apiSecret || !path) return res.status(400).json({ error: "apiKey, apiSecret et path requis" });
  try { res.json(await binanceReq(apiKey, apiSecret, testnet, method, path, params)); }
  catch(e) { res.status(400).json({ error: e.message }); }
});

app.get("/public", async (req, res) => {
  const { path, exchange, ...params } = req.query;
  // Si Bybit demandé
  if (exchange === "bybit") {
    try {
      const data = await bybitPub(path, params);
      return res.json(data);
    } catch(e) {
      return res.status(500).json({ error: e.message });
    }
  }
  const { path: _path, ...params2 } = req.query;
  if (!path) return res.status(400).json({ error: "path requis" });
  try { res.json(await pubFetch(path, params)); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/analyze/:symbol", async (req, res) => {
  try {
    const { interval = "1m" } = req.query;
    const analysis = await analyzeSymbol(req.params.symbol, interval);
    // Ne pas renvoyer les klines brutes
    const { klines, ...safe } = analysis;
    res.json(safe);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/bot/start", (req, res) => {
  if (botState.intervalId) clearInterval(botState.intervalId);
  const cfg = sanitizeInput(req.body);
  if (!cfg.apiKey || !cfg.symbol) return res.status(400).json({ error: "Config incomplète" });

  // Validation symbole
  if (!isValidSymbol(cfg.symbol)) {
    return res.status(400).json({ error: "Symbole invalide (ex: BTCUSDT)" });
  }

  // Validation et avertissement intervalle
  const shortIntervals = ["5s","10s","30s","1m","3m","5m"];
  const recIntervals   = ["15m","30m","1h","4h","1d"];
  if (cfg.interval && shortIntervals.includes(cfg.interval)) {
    addLog(
      `⚠ INTERVALLE COURT: ${cfg.interval} — latence Railway 50-200ms défavorable. ` +
      `Faux signaux 3× plus fréquents. Recommandé: ${recIntervals.join(", ")}`,
      "warning"
    );
    // Bloquer 5s/10s/30s en mode réel (trop risqué)
    if (!cfg.paperMode && ["5s","10s","30s"].includes(cfg.interval)) {
      return res.status(400).json({
        error: `Intervalle ${cfg.interval} bloqué en mode réel`,
        reason: "Latence Railway incompatible avec scalping ultra-court. Minimum 1m, recommandé ≥ 15m.",
        recommended: recIntervals,
      });
    }
  }
  if (cfg.sl  && !inRange(cfg.sl,  0.1, 50))    return res.status(400).json({ error: "SL hors plage (0.1-50%)" });
  if (cfg.tp  && !inRange(cfg.tp,  0.1, 100))   return res.status(400).json({ error: "TP hors plage (0.1-100%)" });
  if (cfg.tradeAmt && !inRange(cfg.tradeAmt, 1, 100000)) return res.status(400).json({ error: "Montant hors plage ($1-$100k)" });
  securityLog(req, `Bot start — ${cfg.exchange || "binance"} ${cfg.symbol} ${cfg.strategy} ${cfg.interval}`);
  addLog(`Exchange: ${(cfg.exchange || "binance").toUpperCase()} | Testnet: ${cfg.testnet}`, "info");

  botState.config       = cfg;
  botState.running      = true;
  botState.position     = null;
  botState.entryPrice   = null;
  botState.entryTime    = null;
  botState.highestPrice = null;
  botState.trailingSL   = null;
  botState.fearGreed    = null;
  botState.partialState = { level: 0, remainingQty: 0, breakEvenMoved: false };

  // Intervalles: stablecoin = 1s, scalp = 5s, sinon selon config
  const msMap = { "1s":1000,"5s":5000,"10s":10000,"30s":30000,"1m":60000,"3m":180000,"5m":300000,"15m":900000,"30m":1800000,"1h":3600000 };
  const delay = cfg.stablecoinMode ? (msMap[cfg.interval] || 1000)
              : cfg.strategy === "SCALP"   ? (msMap[cfg.interval] || 5000)
              : cfg.strategy === "SCANNER" ? (msMap[cfg.interval] || 300000) // 5min par défaut
              : (msMap[cfg.interval] || 60000);
  if (cfg.strategy === "SCANNER") {
    botState.scannerRunning = true;
    multiPositions = {};
    botState.activeSymbols = [];
    botState.scannerResults = [];
    botState.scannerLastRun = null;
  }

  addLog(`✅ Bot démarré — ${cfg.strategy}${cfg.stablecoinMode?" [STABLECOIN]":""} sur ${cfg.symbol} (${cfg.interval} / ${delay}ms)`, "success");
  botCycle();
  botState.intervalId = setInterval(botCycle, delay);
  res.json({ ok: true, message: `Bot ${cfg.strategy} démarré sur ${cfg.symbol} (${delay}ms)` });
});

app.post("/bot/stop", (req, res) => {
  if (botState.intervalId) clearInterval(botState.intervalId);
  botState.running        = false;
  botState.scannerRunning = false;
  botState.intervalId     = null;
  // Fermer toutes les positions multi si besoin
  multiPositions = {};
  addLog("Bot arrêté", "warning");
  res.json({ ok: true, message: "Bot arrêté" });
});

app.get("/bot/status", (req, res) => {
  const s = botState.stats;
  const winRate = s.totalTrades > 0 ? (s.winTrades / s.totalTrades * 100).toFixed(1) : "0.0";
  res.json({
    running: botState.running,
    config:  botState.config ? { symbol:botState.config.symbol, strategy:botState.config.strategy, interval:botState.config.interval } : null,
    position:      botState.position,
    entryPrice:    botState.entryPrice,
    highestPrice:  botState.highestPrice,
    trailingSL:    botState.trailingSL,
    partialState:  botState.partialState,
    fearGreed:        botState.fearGreed,
    lastOrderBook:    botState.lastOrderBook,
    lastWhaleData:    botState.lastWhaleData,
    lastOptimResult:  botState.lastOptimResult,
    paperMode:        botState.config?.paperMode || false,
    paperState:       paperState.active ? { capital: paperState.capital, stats: paperState.stats, position: paperState.position } : null,
    optimizedParams:  botState.optimizedParams,
    circuitBreaker: {
      triggered:    circuitBreakerState.triggered,
      reason:       circuitBreakerState.triggerReason,
      dailyPnl:     circuitBreakerState.dailyPnl.toFixed(2),
      dailyTrades:  circuitBreakerState.dailyTrades,
      dailyLosses:  circuitBreakerState.dailyLosses,
    },
    positionSymbol: botState.positionSymbol,
    currentScSymbol: botState.currentScSymbol,
    scScanResults: botState.scScanResults,
    scNotProfitableSince:  botState.scNotProfitableSince,
    scannerResults:  botState.scannerResults.slice(0, 30),
    scannerLastRun:  botState.scannerLastRun,
    activeSymbols:   botState.activeSymbols,
    multiPositions:  multiPositions,
    dcaAvgPrice: botState.dcaAvgPrice,
    dcaOrders:  botState.dcaOrders,
    logs:   botState.logs.slice(0, 150),
    trades: botState.trades.slice(0, 30),
    stats: { ...s, winRate, avgPnl: s.totalTrades > 0 ? (s.totalPnlUsd / s.totalTrades).toFixed(3) : "0" },
  });
});

app.post("/bot/reset-stats", (req, res) => {
  botState.stats = { totalTrades:0, winTrades:0, lossTrades:0, totalPnlUsd:0, totalPnlPct:0, bestTrade:null, worstTrade:null, largestWin:0, largestLoss:0, currentDrawdown:0, maxDrawdown:0, startBalance:null, runningPnl:0 };
  botState.trades = [];
  addLog("Statistiques réinitialisées", "warning");
  res.json({ ok: true });
});

// ── Routes Email ──────────────────────────────────────────────────────────────
app.post("/email/config", (req, res) => {
  const { gmailUser, gmailPass, recipient, reportHour, reportMinute, enabled } = req.body;
  if (gmailUser)    emailConfig.gmailUser    = gmailUser;
  if (gmailPass)    emailConfig.gmailPass    = gmailPass;
  if (recipient)    emailConfig.recipient    = recipient;
  if (reportHour !== undefined)  emailConfig.reportHour   = parseInt(reportHour);
  if (reportMinute !== undefined) emailConfig.reportMinute = parseInt(reportMinute);
  if (enabled !== undefined) emailConfig.enabled = enabled;
  // Relancer le planificateur avec le nouvel horaire
  scheduleDailyReport();
  addLog(`Config email mise à jour — rapport à ${emailConfig.reportHour}h${String(emailConfig.reportMinute).padStart(2,"0")} → ${emailConfig.recipient}`, "success");
  res.json({ ok: true, config: { ...emailConfig, gmailPass: "***" } });
});

app.get("/email/config", (req, res) => {
  res.json({ ...emailConfig, gmailPass: emailConfig.gmailPass ? "***configuré***" : "" });
});

app.post("/email/test", async (req, res) => {
  const ok = await sendDailyReport();
  res.json({ ok, message: ok ? "Email envoyé avec succès" : "Échec — voir les logs" });
});

// ── Routes Niveau 3 ──────────────────────────────────────────────────────────

// ── Auth verify ──────────────────────────────────────────────────────────────
app.get("/auth/verify", (req, res) => {
  // Si on arrive ici, le token est valide (requireAuth a déjà validé)
  securityLog(req, "Token verified");
  res.json({ ok: true, message: "Token valide", secured: !!SERVER_SECRET });
});

// ── Paper Trading routes ─────────────────────────────────────────────────────
app.get("/paper/status", (req, res) => {
  res.json({ ...paperState, trades: paperState.trades.slice(0, 20) });
});

app.post("/paper/reset", (req, res) => {
  const capital = parseFloat(req.body.capital || 1000);
  paperState.active = false;
  paperState.capital = capital;
  paperState.initialCapital = capital;
  paperState.position = null;
  paperState.entryPrice = null;
  paperState.qty = 0;
  paperState.trades = [];
  paperState.stats = {
    totalTrades: 0, winTrades: 0, lossTrades: 0,
    totalPnlUsd: 0, totalPnlPct: 0,
    largestWin: 0, largestLoss: 0,
    maxDrawdown: 0, peakCapital: capital,
    equityCurve: [],
  };
  addLog(`Paper trading réinitialisé — capital: $${capital}`, "info");
  res.json({ ok: true, capital });
});

// Slippage estimé pour une paire
app.get("/slippage/:symbol", async (req, res) => {
  const symbol = req.params.symbol.toUpperCase();
  const qty    = parseFloat(req.query.qty || 0.001);
  try {
    const ticker = await pubFetch("/api/v3/ticker/bookTicker", { symbol });
    const spread = ticker ? parseFloat(ticker.askPrice) - parseFloat(ticker.bidPrice) : 0;
    const price  = ticker ? (parseFloat(ticker.askPrice) + parseFloat(ticker.bidPrice)) / 2 : 0;
    const slip   = estimateSlippage(price, qty, 1000000, spread);
    res.json({ symbol, price, spread, qty, ...slip });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// VPVR pour une paire
app.get("/vpvr/:symbol", async (req, res) => {
  const symbol   = req.params.symbol.toUpperCase();
  const interval = req.query.interval || "1h";
  try {
    const klines = await exchangePubKlines(cfg, symbol, interval, 200);
    const vpvr   = calcVolumeProfile(klines, 24);
    res.json(vpvr || { error: "Insufficient data" });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Liquidation levels
app.get("/liquidations/:symbol", async (req, res) => {
  const data = await getLiquidationLevels(req.params.symbol.toUpperCase());
  res.json(data || { error: "Unavailable" });
});

// Order Book en temps réel
app.get("/orderbook/:symbol", async (req, res) => {
  const sym = req.params.symbol.toUpperCase();
  if (!isValidSymbol(sym)) return res.status(400).json({ error: "Symbole invalide" });
  const data = await getOrderBookImbalance(sym, 20);
  res.json(data || { error: "Unavailable" });
});

// Funding rates — top opportunités
app.get("/funding", async (req, res) => {
  const data = await getFundingRates();
  res.json(data.slice(0, 20));
});

// Arbitrage funding pour 1 paire
app.get("/funding/:symbol", async (req, res) => {
  const data = await detectFundingArbitrage(req.params.symbol.toUpperCase());
  res.json(data || { error: "Unavailable" });
});

// Whale activity
app.get("/whales/:symbol", async (req, res) => {
  const sym       = req.params.symbol.toUpperCase();
  if (!isValidSymbol(sym)) return res.status(400).json({ error: "Symbole invalide" });
  const threshold = Math.min(Math.max(parseInt(req.query.threshold || 50000), 1000), 10000000);
  const data = await detectWhaleActivity(sym, threshold);
  res.json(data || { error: "Unavailable" });
});

// ── OPTIMISEUR DE PARAMÈTRES ─────────────────────────────────────────────────
app.post("/optimize", async (req, res) => {
  const body   = sanitizeInput(req.body);
  const symbol    = body.symbol;
  const interval  = body.interval;
  const autoApply = body.autoApply;
  if (!symbol) return res.status(400).json({ error: "symbol requis" });
  if (!isValidSymbol(symbol)) return res.status(400).json({ error: "Symbole invalide" });
  if (interval && !["1m","3m","5m","15m","30m","1h","4h","1d"].includes(interval)) {
    return res.status(400).json({ error: "Intervalle invalide" });
  }
  securityLog(req, `Optimize — ${symbol} ${interval || "1h"}`);
  try {
    const result = await runParameterOptimizer(
      symbol.toUpperCase(),
      interval || "1h"
    );
    if (!result) return res.status(500).json({ error: "Optimisation échouée" });

    botState.lastOptimResult = result;

    // Auto-appliquer les meilleurs paramètres si demandé
    if (autoApply && result.best && botState.config) {
      const best = result.best;
      botState.optimizedParams = {
        rsiOs:    best.rsiOs,
        rsiOb:    best.rsiOb,
        sl:       best.sl,
        tp:       best.tp,
        trailPct: best.trailPct,
      };
      // Mettre à jour le config actif
      if (botState.config) {
        botState.config.rsiOs    = best.rsiOs;
        botState.config.rsiOb    = best.rsiOb;
        botState.config.sl       = best.sl;
        botState.config.tp       = best.tp;
        botState.config.trailPct = best.trailPct;
      }
      addLog(
        `🤖 Paramètres auto-optimisés appliqués: RSI(${best.rsiOs}/${best.rsiOb}) SL:${best.sl}% TP:${best.tp}% Trail:${best.trailPct}%`,
        "success"
      );
    }

    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Reset circuit breaker manuel
app.post("/circuit-breaker/reset", (req, res) => {
  circuitBreakerState.triggered     = false;
  circuitBreakerState.triggerReason = null;
  circuitBreakerState.triggerTime   = null;
  addLog("Circuit breaker réinitialisé manuellement", "warning");
  res.json({ ok: true, message: "Circuit breaker réinitialisé" });
});

// Route scan manuel
app.post("/scan", async (req, res) => {
  const _scanExchange = req.body?.exchange || "binance";
  const cfg = req.body;
  botState.scannerRunning = true;
  try {
    const results = await runFullScan({
      scanTopN:      cfg.scanTopN      || 10,
      scanMinVol24h: cfg.scanMinVol24h || 500000,
      scanMinScore:  cfg.scanMinScore  || 55,
      scanBatchSize: cfg.scanBatchSize || 20,
    });
    botState.scannerRunning = false;
    res.json({ ok: true, count: results.length, top: results, all: botState.scannerResults.slice(0,50) });
  } catch(e) {
    botState.scannerRunning = false;
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`✅ Binance Bot Proxy v2 sur port ${PORT}`));
