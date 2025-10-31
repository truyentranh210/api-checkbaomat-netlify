// netlify/functions/api.js
import * as cheerio from "cheerio";
import dns from "dns/promises";
import tls from "tls";
import { URL } from "url";

/*
  Updated Deep Scanner API for Netlify Functions
  - safe dynamic axios import via getAxios()
  - endpoints:
      /news?source=vnexpress|dantri|24h
      /scan?url=...&deep=true&maxLinks=20&followExternal=false
*/

let _axios = null;
async function getAxios() {
  if (_axios) return _axios;
  try {
    _axios = (await import("axios")).default;
    return _axios;
  } catch (err) {
    // rethrow with clearer message
    throw new Error("Failed to import axios dynamically: " + (err && err.message ? err.message : err));
  }
}

export async function handler(event) {
  // Normalize path from Netlify function invocation
  // event.path usually like "/.netlify/functions/api/scan" or "/.netlify/functions/api/news"
  const basePrefix = "/.netlify/functions/api";
  let path = event.path || "";
  if (path.startsWith(basePrefix)) {
    path = path.slice(basePrefix.length);
  }
  path = path.replace(/^\/+|\/+$/g, ""); // trim leading/trailing slashes

  // Default route support: allow calling /api/scan or direct /scan if rewrites applied
  const parts = path.split("/").filter(Boolean);
  const endpoint = parts[0] || (event.rawPath ? event.rawPath.replace(/^\/+/, "").split("/")[0] : "");

  try {
    if (endpoint === "news") return await getNews(event);
    if (endpoint === "scan") return await scanSite(event);

    return {
      statusCode: 404,
      body: JSON.stringify({ error: "Not Found. Use /news or /scan endpoints." }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message || String(err) }),
    };
  }
}

/* ----------------------------
   /news endpoint
   ---------------------------- */
async function getNews(event) {
  const q = event.queryStringParameters || {};
  const source = (q.source || "vnexpress").toLowerCase();

  const sources = {
    vnexpress: "https://vnexpress.net/",
    dantri: "https://dantri.com.vn/",
    "24h": "https://www.24h.com.vn/",
  };
  const url = sources[source] || sources.vnexpress;

  const axios = await getAxios();
  try {
    const res = await axios.get(url, { timeout: 10000, headers: { "User-Agent": "Netlify-NewsBot/1.0" } });
    const $ = cheerio.load(res.data);
    const articles = [];

    if (source === "vnexpress") {
      $(".item-news a.thumb-art").each((i, el) => {
        if (i >= 10) return;
        articles.push({
          title: ($(el).attr("title") || $(el).text() || "").trim(),
          link: $(el).attr("href"),
        });
      });
    } else if (source === "dantri") {
      $(".news-item a").each((i, el) => {
        if (i >= 10) return;
        const href = $(el).attr("href") || "";
        articles.push({ title: ($(el).text() || "").trim(), link: href.startsWith("http") ? href : `https://dantri.com.vn${href}` });
      });
    } else if (source === "24h") {
      $(".cate-24h-foot-home a").each((i, el) => {
        if (i >= 10) return;
        const href = $(el).attr("href") || "";
        articles.push({ title: ($(el).text() || "").trim(), link: href.startsWith("http") ? href : `https://www.24h.com.vn${href}` });
      });
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ source, count: articles.length, data: articles }, null, 2),
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: "Failed to fetch news", details: err.message || String(err) }) };
  }
}

/* ----------------------------
   /scan endpoint (deep)
   Query params:
     - url (required)
     - deep (true|1)
     - maxLinks (number)
     - followExternal (true|false)
   ---------------------------- */
async function scanSite(event) {
  const q = event.queryStringParameters || {};
  const rawUrl = q.url;
  const deep = q.deep === "true" || q.deep === "1";
  const maxLinks = Math.min(Math.max(parseInt(q.maxLinks || "20", 10) || 20, 1), 100);
  const followExternal = q.followExternal === "true";

  if (!rawUrl) return { statusCode: 400, body: JSON.stringify({ error: "Missing ?url= parameter" }) };

  let target;
  try {
    target = new URL(rawUrl);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid URL", details: e.message || String(e) }) };
  }

  const axios = await getAxios();
  const result = {
    url: target.href,
    host: target.hostname,
    protocol: target.protocol,
    timestamp: new Date().toISOString(),
    summary: {},
    details: {},
  };

  // 1) Basic fetch (GET) with timing
  let primaryResp = null;
  try {
    const t0 = Date.now();
    primaryResp = await axios.get(target.href, {
      timeout: 20000,
      maxRedirects: 10,
      validateStatus: null,
      headers: { "User-Agent": "Netlify-DeepScan/1.0" },
    });
    result.summary.responseTimeMs = Date.now() - t0;
    result.summary.status = primaryResp.status;
    result.summary.reachable = primaryResp.status < 400;
    result.details.http = {
      status: primaryResp.status,
      finalUrl: primaryResp.request?.res?.responseUrl || target.href,
      headers: primaryResp.headers,
      contentType: primaryResp.headers["content-type"] || null,
      sizeBytes: calculateBodySize(primaryResp.data),
      setCookie: primaryResp.headers["set-cookie"] || null,
    };
  } catch (err) {
    result.summary.reachable = false;
    result.details.fetchError = err.message || String(err);
    // Continue to perform DNS/TLS checks even if fetch failed
  }

  // 2) TLS certificate (if HTTPS)
  if (target.protocol === "https:") {
    try {
      const cert = await getCertificate(target.hostname);
      result.details.tls = {
        subject: cert.subject || null,
        issuer: cert.issuer || null,
        valid_from: cert.valid_from || null,
        valid_to: cert.valid_to || null,
        days_to_expiry: calcDaysToExpiry(cert.valid_to),
        valid_now: isCertValidNow(cert),
        raw: cert,
      };
    } catch (e) {
      result.details.tls_error = e.message || String(e);
    }
  } else {
    result.details.tls = { note: "Not HTTPS" };
  }

  // 3) Security headers quick checks (if http response present)
  const headers = primaryResp?.headers || {};
  result.details.securityHeaders = {
    hsts: !!headers["strict-transport-security"],
    csp: !!headers["content-security-policy"],
    xFrameOptions: !!headers["x-frame-options"],
    xContentTypeOptions: !!headers["x-content-type-options"],
    referrerPolicy: !!headers["referrer-policy"],
    permissionsPolicy: !!(headers["permissions-policy"] || headers["feature-policy"]),
    cors: !!headers["access-control-allow-origin"],
    server: headers["server"] || headers["x-powered-by"] || null,
  };

  // 4) Cookies analysis
  if (primaryResp?.headers?.["set-cookie"]) {
    result.details.cookies = analyzeCookies(primaryResp.headers["set-cookie"]);
  }

  // 5) Mixed content scan (HTTPS only)
  if (target.protocol === "https:" && primaryResp?.data) {
    result.details.mixedContent = findMixedContent(primaryResp.data);
  }

  // 6) Important resources: robots.txt, sitemap.xml, security.txt, favicon, manifest
  try {
    result.details.resources = {};
    result.details.resources.robots = await tryFetchText(new URL("/robots.txt", target.origin).href, axios);
    result.details.resources.sitemap = await tryFetchText(new URL("/sitemap.xml", target.origin).href, axios);
    result.details.resources.securitytxt = await tryFetchText(new URL("/.well-known/security.txt", target.origin).href, axios);
    result.details.resources.favicon = await tryFetchStatus(new URL("/favicon.ico", target.origin).href, axios);
    result.details.resources.manifest = await tryFetchText(new URL("/site.webmanifest", target.origin).href, axios);
    // count sitemap URLs if present
    if (result.details.resources.sitemap?.ok && result.details.resources.sitemap.text) {
      const matches = result.details.resources.sitemap.text.match(/<loc>(.*?)<\/loc>/g);
      result.details.resources.sitemap.count = matches ? matches.length : 0;
    }
  } catch (e) {
    result.details.resources_error = e.message || String(e);
  }

  // 7) DNS checks (MX, TXT, NS, A, SOA) - best-effort
  try {
    const [mxP, txtP, nsP, aP, soaP] = await Promise.allSettled([
      dns.resolveMx(target.hostname).catch(() => null),
      dns.resolveTxt(target.hostname).catch(() => null),
      dns.resolveNs(target.hostname).catch(() => null),
      dns.resolve4(target.hostname).catch(() => null),
      dns.resolveSoa(target.hostname).catch(() => null),
    ]);
    result.details.dns = {
      mx: mxP.status === "fulfilled" ? mxP.value : null,
      txt: txtP.status === "fulfilled" ? txtP.value : null,
      ns: nsP.status === "fulfilled" ? nsP.value : null,
      a: aP.status === "fulfilled" ? aP.value : null,
      soa: soaP.status === "fulfilled" ? soaP.value : null,
      has_spf: Array.isArray(txtP.value) ? txtP.value.flat().some(t => t.includes("v=spf1")) : false,
    };
  } catch (e) {
    result.details.dns_error = e.message || String(e);
  }

  // 8) TLS cipher / protocol info
  if (target.protocol === "https:") {
    try {
      const tlsInfo = await tryTlsInfo(target.hostname);
      result.details.tls_info = tlsInfo;
    } catch (e) {
      result.details.tls_info_error = e.message || String(e);
    }
  }

  // 9) Redirect chain analysis (manual head-follow)
  try {
    result.details.redirectChain = await getRedirectChain(target.href, axios);
  } catch (e) {
    result.details.redirectChainError = e.message || String(e);
  }

  // 10) Deep crawl (if requested)
  if (deep && primaryResp?.data) {
    try {
      const $ = cheerio.load(primaryResp.data);
      const links = new Set();
      $("a[href]").each((_, el) => {
        if (links.size >= maxLinks) return;
        const href = $(el).attr("href");
        if (!href) return;
        try {
          const u = new URL(href, target.origin);
          if (!followExternal && u.hostname !== target.hostname) return;
          if (u.protocol.startsWith("http")) links.add(u.href);
        } catch (_) { /* skip invalid */ }
      });

      const list = Array.from(links).slice(0, maxLinks);
      result.details.deep = { total: list.length, sample: [] };

      // parallel checks but protected (limited concurrency would be ideal; here use Promise.all with caution)
      const checks = await Promise.all(list.map(async (link) => {
        try {
          const r = await axios.head(link, { timeout: 8000, maxRedirects: 5, validateStatus: null, headers: { "User-Agent": "Netlify-DeepScan/1.0" } });
          return {
            url: link,
            status: r.status,
            contentType: r.headers["content-type"] || null,
            hasCSP: !!r.headers["content-security-policy"],
            hasHSTS: !!r.headers["strict-transport-security"],
          };
        } catch (e) {
          return { url: link, error: e.message || String(e) };
        }
      }));
      result.details.deep.sample = checks;
    } catch (e) {
      result.details.deep_error = e.message || String(e);
    }
  }

  // 11) Basic heuristic triage score
  result.summary.score = computeScore(result);

  return { statusCode: 200, body: JSON.stringify(result, null, 2) };
}

/* ----------------------------
   Helper utilities
   ---------------------------- */

function calculateBodySize(data) {
  try {
    if (!data) return 0;
    if (typeof data === "string") return Buffer.byteLength(data, "utf8");
    if (Buffer.isBuffer(data)) return data.length;
    return Buffer.byteLength(JSON.stringify(data), "utf8");
  } catch {
    return null;
  }
}

async function tryFetchText(url, axiosInstance) {
  try {
    const r = await axiosInstance.get(url, { timeout: 8000, maxRedirects: 5, validateStatus: null });
    return { ok: r.status >= 200 && r.status < 400, status: r.status, text: typeof r.data === "string" ? r.data : JSON.stringify(r.data).slice(0, 4000) };
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}

async function tryFetchStatus(url, axiosInstance) {
  try {
    const r = await axiosInstance.head(url, { timeout: 8000, maxRedirects: 5, validateStatus: null });
    return { ok: r.status >= 200 && r.status < 400, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}

function analyzeCookies(setCookieArray) {
  const arr = Array.isArray(setCookieArray) ? setCookieArray : [setCookieArray];
  return arr.map((c) => {
    const str = String(c);
    const sameSiteMatch = str.match(/;\s*samesite=(\w+)/i);
    return {
      raw: str,
      secure: /;\s*secure/i.test(str),
      httpOnly: /;\s*httponly/i.test(str),
      sameSite: sameSiteMatch ? sameSiteMatch[1] : null,
    };
  });
}

function findMixedContent(html) {
  try {
    const $ = cheerio.load(html || "");
    const insecure = [];
    $("img[src], script[src], link[href], iframe[src], source[src]").each((_, el) => {
      const attr = el.name === "link" ? $(el).attr("href") : $(el).attr("src");
      if (attr && typeof attr === "string" && attr.startsWith("http://")) insecure.push(attr);
    });
    return { insecureCount: insecure.length, examples: insecure.slice(0, 20) };
  } catch (e) {
    return { insecureCount: 0, error: e.message || String(e) };
  }
}

function calcDaysToExpiry(valid_to) {
  try {
    if (!valid_to) return null;
    const d = new Date(valid_to);
    const diff = d - new Date();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  } catch {
    return null;
  }
}

function isCertValidNow(cert) {
  try {
    if (!cert || !cert.valid_from || !cert.valid_to) return false;
    const from = new Date(cert.valid_from);
    const to = new Date(cert.valid_to);
    const now = new Date();
    return now >= from && now <= to;
  } catch {
    return false;
  }
}

async function getCertificate(hostname) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, hostname, { servername: hostname, timeout: 8000 }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        socket.end();
        if (!cert || Object.keys(cert).length === 0) return reject(new Error("No certificate retrieved"));
        resolve(cert);
      } catch (e) {
        socket.end();
        reject(e);
      }
    });
    socket.on("error", (e) => reject(e));
    socket.on("timeout", () => { socket.destroy(); reject(new Error("TLS timeout")); });
  });
}

async function tryTlsInfo(hostname) {
  return new Promise((resolve, reject) => {
    const s = tls.connect(443, hostname, { servername: hostname, timeout: 8000 }, () => {
      try {
        const cipher = s.getCipher();
        const proto = s.getProtocol();
        s.end();
        resolve({ cipher, protocol: proto || null });
      } catch (e) {
        s.end();
        reject(e);
      }
    });
    s.on("error", (e) => reject(e));
    s.on("timeout", () => { s.destroy(); reject(new Error("TLS info timeout")); });
  });
}

async function getRedirectChain(startUrl, axiosInstance) {
  const chain = [];
  let current = startUrl;
  for (let i = 0; i < 10; i++) {
    try {
      const r = await axiosInstance.head(current, { timeout: 8000, maxRedirects: 0, validateStatus: null });
      chain.push({ url: current, status: r.status, location: r.headers.location || null });
      if (r.status >= 300 && r.status < 400 && r.headers.location) {
        const next = new URL(r.headers.location, current).href;
        if (next === current) break;
        current = next;
        continue;
      }
      break;
    } catch (e) {
      chain.push({ url: current, error: e.message || String(e) });
      break;
    }
  }
  return chain;
}

function computeScore(result) {
  let score = 100;
  if (!result.summary.reachable) return 0;
  const h = result.details.securityHeaders || {};
  if (!h.hsts) score -= 20;
  if (!h.csp) score -= 20;
  if (!h.xFrameOptions) score -= 10;
  if (!h.xContentTypeOptions) score -= 10;
  if (result.details.mixedContent && result.details.mixedContent.insecureCount > 0) score -= 15;
  if (result.details.tls && typeof result.details.tls.days_to_expiry === "number" && result.details.tls.days_to_expiry < 14) score -= 10;
  return Math.max(0, score);
}
