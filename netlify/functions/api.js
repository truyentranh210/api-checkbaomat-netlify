// netlify/functions/api.js
import * as cheerio from "cheerio";
import dns from "dns/promises";
import tls from "tls";
import { URL } from "url";

// 🧩 Import axios an toàn cho Netlify (ESM + fallback)
let axios;
try {
  axios = (await import("axios")).default;
} catch (err) {
  console.error("Axios dynamic import failed:", err);
  throw err;
}

/*
 API: Deep Security Scanner
 ├ /news?source=vnexpress|dantri|24h
 └ /scan?url=https://example.com&deep=true
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

/* ============ 📰 /news endpoint ============ */
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
    const { data } = await axios.get(url, { timeout: 8000 });
    const $ = cheerio.load(data);
    const list = [];

    if (source === "vnexpress") {
      $(".item-news a.thumb-art").each((i, el) => {
        if (i < 10)
          list.push({ title: $(el).attr("title") || $(el).text().trim(), link: $(el).attr("href") });
      });
    } else if (source === "dantri") {
      $(".news-item a").each((i, el) => {
        if (i < 10)
          list.push({ title: $(el).text().trim(), link: "https://dantri.com.vn" + $(el).attr("href") });
      });
    } else if (source === "24h") {
      $(".cate-24h-foot-home a").each((i, el) => {
        if (i < 10)
          list.push({ title: $(el).text().trim(), link: "https://www.24h.com.vn" + $(el).attr("href") });
      });
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ source, count: list.length, data: list }, null, 2)
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
}

/* ============ 🔍 /scan endpoint (deep) ============ */
async function scanSite(event) {
  const q = event.queryStringParameters || {};
  const rawUrl = q.url;
  const deep = q.deep === "true" || q.deep === "1";
  const maxLinks = parseInt(q.maxLinks || "20", 10);
  if (!rawUrl)
    return { statusCode: 400, body: JSON.stringify({ error: "Missing ?url=" }) };

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

  // ⚡ Fetch website
  let resp;
  const t0 = Date.now();
  try {
    resp = await axios.get(target.href, { timeout: 15000, validateStatus: null });
    result.summary.status = resp.status;
    result.summary.reachable = resp.status < 400;
    result.summary.responseTimeMs = Date.now() - t0;
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }

  // 🔐 TLS certificate
  if (target.protocol === "https:") {
    try {
      result.details.tls = await getCertificate(target.hostname);
    } catch (e) {
      result.details.tls_error = e.message;
    }
  }

  // 🧱 Security headers
  const h = resp.headers || {};
  result.details.securityHeaders = {
    hsts: !!h["strict-transport-security"],
    csp: !!h["content-security-policy"],
    xFrame: !!h["x-frame-options"],
    xContentType: !!h["x-content-type-options"],
    cors: !!h["access-control-allow-origin"]
  };

  // 🍪 Cookies
  if (h["set-cookie"]) result.details.cookies = analyzeCookies(h["set-cookie"]);

  // 🌐 DNS info
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

  // 🧩 Deep crawl
  if (deep && resp.data) {
    const $ = cheerio.load(resp.data);
    const links = new Set();
    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (href && links.size < maxLinks) {
        try {
          const u = new URL(href, target.origin);
          if (u.hostname === target.hostname) links.add(u.href);
        } catch {}
      }
    });
    const arr = [...links];
    const res = await Promise.all(arr.map(async (u) => {
      try {
        const r = await axios.head(u, { timeout: 6000, validateStatus: null });
        return { url: u, status: r.status, hasCSP: !!r.headers["content-security-policy"] };
      } catch (e) {
        return { url: u, error: e.message };
      }
    }));
    result.details.deep = { total: arr.length, sample: res };
  }

  return { statusCode: 200, body: JSON.stringify(result, null, 2) };
}

/* ============ Helpers ============ */
async function getCertificate(host) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, host, { servername: host, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      resolve({
        subject: cert.subject,
        issuer: cert.issuer,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to
      });
    });
    socket.on("error", reject);
    socket.on("timeout", () => reject(new Error("TLS timeout")));
  });
}

function analyzeCookies(list) {
  const arr = Array.isArray(list) ? list : [list];
  return arr.map((c) => ({
    raw: c,
    secure: /;\\s*secure/i.test(c),
    httpOnly: /;\\s*httponly/i.test(c),
    sameSite: (c.match(/;\\s*samesite=(\\w+)/i) || [])[1] || null
  }));
}
