// ✅ Safe imports (works perfectly on Netlify Node 18/20)
import axios from "axios";
import * as cheerio from "cheerio";
import dns from "dns/promises";
import tls from "tls";
import { URL } from "url";

/*
  🔍 Deep Web Scanner API
  Endpoints:
    /news?source=vnexpress|dantri|24h
    /scan?url=https://example.com&deep=true
*/

export async function handler(event) {
  const path = event.path.replace("/.netlify/functions/api", "").replace("/", "");

  if (path.startsWith("news")) return getNews(event);
  if (path.startsWith("scan")) return scanSite(event);

  return {
    statusCode: 404,
    body: JSON.stringify({ error: "Not Found. Use /news or /scan endpoints." })
  };
}

/* ========================= 📰 NEWS API ========================= */
async function getNews(event) {
  const q = event.queryStringParameters || {};
  const source = (q.source || "vnexpress").toLowerCase();

  const sources = {
    vnexpress: "https://vnexpress.net/",
    dantri: "https://dantri.com.vn/",
    "24h": "https://www.24h.com.vn/"
  };
  const url = sources[source] || sources.vnexpress;

  try {
    const { data } = await axios.get(url, { timeout: 10000, headers: { "User-Agent": "Netlify-NewsBot/1.0" } });
    const $ = cheerio.load(data);
    const list = [];

    if (source === "vnexpress") {
      $(".item-news a.thumb-art").each((i, el) => {
        if (i < 10) list.push({ title: $(el).attr("title") || $(el).text().trim(), link: $(el).attr("href") });
      });
    } else if (source === "dantri") {
      $(".news-item a").each((i, el) => {
        if (i < 10) list.push({ title: $(el).text().trim(), link: "https://dantri.com.vn" + $(el).attr("href") });
      });
    } else if (source === "24h") {
      $(".cate-24h-foot-home a").each((i, el) => {
        if (i < 10) list.push({ title: $(el).text().trim(), link: "https://www.24h.com.vn" + $(el).attr("href") });
      });
    }

    return { statusCode: 200, body: JSON.stringify({ source, count: list.length, data: list }, null, 2) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: "Failed to fetch news", details: e.message }) };
  }
}

/* ========================= 🔍 SCAN API ========================= */
async function scanSite(event) {
  const q = event.queryStringParameters || {};
  const rawUrl = q.url;
  const deep = q.deep === "true" || q.deep === "1";
  const maxLinks = Math.min(parseInt(q.maxLinks || "20", 10), 50);
  if (!rawUrl) return { statusCode: 400, body: JSON.stringify({ error: "Missing ?url=" }) };

  let target;
  try {
    target = new URL(rawUrl);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid URL" }) };
  }

  const result = {
    url: target.href,
    host: target.hostname,
    timestamp: new Date().toISOString(),
    summary: {},
    details: {}
  };

  // 1️⃣ HTTP fetch
  let resp = null;
  try {
    const t0 = Date.now();
    resp = await axios.get(target.href, { timeout: 20000, validateStatus: null, headers: { "User-Agent": "Netlify-DeepScan/1.0" } });
    result.summary.responseTimeMs = Date.now() - t0;
    result.summary.status = resp.status;
    result.summary.reachable = resp.status < 400;
  } catch (e) {
    result.summary.reachable = false;
    result.details.fetchError = e.message;
  }

  // 2️⃣ TLS certificate
  if (target.protocol === "https:") {
    try {
      const cert = await getCertificate(target.hostname);
      result.details.tls = {
        subject: cert.subject,
        issuer: cert.issuer,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        days_to_expiry: calcDaysToExpiry(cert.valid_to),
        valid_now: isCertValidNow(cert)
      };
    } catch (e) {
      result.details.tls_error = e.message;
    }
  }

  // 3️⃣ Headers & Cookies
  const h = resp?.headers || {};
  result.details.securityHeaders = {
    hsts: !!h["strict-transport-security"],
    csp: !!h["content-security-policy"],
    xFrame: !!h["x-frame-options"],
    xContent: !!h["x-content-type-options"],
    cors: !!h["access-control-allow-origin"]
  };

  if (h["set-cookie"]) result.details.cookies = analyzeCookies(h["set-cookie"]);

  // 4️⃣ DNS
  try {
    const [mx, txt, ns] = await Promise.all([
      dns.resolveMx(target.hostname).catch(() => null),
      dns.resolveTxt(target.hostname).catch(() => null),
      dns.resolveNs(target.hostname).catch(() => null)
    ]);
    result.details.dns = { mx, ns, txt };
  } catch (e) {
    result.details.dns_error = e.message;
  }

  // 5️⃣ Deep crawl
  if (deep && resp?.data) {
    const $ = cheerio.load(resp.data);
    const links = new Set();
    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      try {
        const u = new URL(href, target.origin);
        if (u.hostname === target.hostname) links.add(u.href);
      } catch {}
    });

    const arr = Array.from(links).slice(0, maxLinks);
    const checks = await Promise.all(arr.map(async (u) => {
      try {
        const r = await axios.head(u, { timeout: 8000, validateStatus: null });
        return { url: u, status: r.status, hasCSP: !!r.headers["content-security-policy"] };
      } catch (e) {
        return { url: u, error: e.message };
      }
    }));
    result.details.deep = { total: arr.length, sample: checks };
  }

  // 6️⃣ Scoring
  result.summary.score = computeScore(result);

  return { statusCode: 200, body: JSON.stringify(result, null, 2) };
}

/* ========================= 🔧 HELPERS ========================= */
function analyzeCookies(list) {
  const arr = Array.isArray(list) ? list : [list];
  return arr.map((c) => ({
    raw: c,
    secure: /; *secure/i.test(c),
    httpOnly: /; *httponly/i.test(c),
    sameSite: (c.match(/; *samesite=(\w+)/i) || [])[1] || null
  }));
}

function calcDaysToExpiry(valid_to) {
  try {
    const d = new Date(valid_to);
    const diff = d - new Date();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  } catch {
    return null;
  }
}

function isCertValidNow(cert) {
  try {
    const from = new Date(cert.valid_from);
    const to = new Date(cert.valid_to);
    const now = new Date();
    return now >= from && now <= to;
  } catch {
    return false;
  }
}

async function getCertificate(host) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, host, { servername: host, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      if (!cert || Object.keys(cert).length === 0) return reject(new Error("No certificate retrieved"));
      resolve(cert);
    });
    socket.on("error", reject);
    socket.on("timeout", () => reject(new Error("TLS timeout")));
  });
}

function computeScore(result) {
  let score = 100;
  if (!result.summary.reachable) return 0;
  const h = result.details.securityHeaders || {};
  if (!h.hsts) score -= 20;
  if (!h.csp) score -= 20;
  if (!h.xFrame) score -= 10;
  if (!h.xContent) score -= 10;
  if (result.details.tls && result.details.tls.days_to_expiry < 14) score -= 10;
  return Math.max(0, score);
}
