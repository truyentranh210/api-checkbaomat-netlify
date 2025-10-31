import axios from "axios";
import * as cheerio from "cheerio";
import dns from "dns/promises";
import tls from "tls";
import { URL } from "url";

/*
 Deep Scanner API for Netlify Functions
 Endpoints:
  - /.netlify/functions/api/news?source=vnexpress|dantri|24h
  - /.netlify/functions/api/scan?url=...&deep=true&maxLinks=20&followExternal=false
*/

export async function handler(event) {
  const basePath = "/.netlify/functions/api";
  const path = event.path.startsWith(basePath) ? event.path.slice(basePath.length + 1) : event.path;
  const endpoint = path.split("/")[0] || "";

  if (endpoint === "news" || event.path.endsWith("/news")) return await getNews(event);
  if (endpoint === "scan" || event.path.endsWith("/scan")) return await scanSite(event);

  return {
    statusCode: 404,
    body: JSON.stringify({ error: "Endpoint not found. Use /news or /scan." }),
  };
}

/* ---------------------------
   /news endpoint (simple)
   --------------------------- */
async function getNews(event) {
  const q = event.queryStringParameters || {};
  const source = (q.source || "vnexpress").toLowerCase();

  const sources = {
    vnexpress: "https://vnexpress.net/",
    dantri: "https://dantri.com.vn/",
    "24h": "https://www.24h.com.vn/",
  };
  const url = sources[source] || sources.vnexpress;
  try {
    const { data } = await axios.get(url, { timeout: 8000 });
    const $ = cheerio.load(data);
    const articles = [];
    if (source === "vnexpress") {
      $(".item-news a.thumb-art").each((i, el) => { if (i < 10) articles.push({ title: $(el).attr("title") || $(el).text().trim(), link: $(el).attr("href") }); });
    } else if (source === "dantri") {
      $(".news-item a").each((i, el) => { if (i < 10) articles.push({ title: $(el).text().trim(), link: "https://dantri.com.vn" + $(el).attr("href") }); });
    } else if (source === "24h") {
      $(".cate-24h-foot-home a").each((i, el) => { if (i < 10) articles.push({ title: $(el).text().trim(), link: "https://www.24h.com.vn" + $(el).attr("href") }); });
    }
    return { statusCode: 200, body: JSON.stringify({ source, count: articles.length, data: articles }, null, 2) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: "Failed to fetch news", details: e.message }) };
  }
}

/* ---------------------------
   /scan endpoint (deep)
   Query params:
    - url (required)
    - deep (true/1 to enable crawling links)
    - maxLinks (default 20)
    - followExternal (true/false) whether to follow external domains during deep scan
   --------------------------- */
async function scanSite(event) {
  const q = event.queryStringParameters || {};
  const rawUrl = q.url;
  const deep = q.deep === "true" || q.deep === "1";
  const maxLinks = parseInt(q.maxLinks || "20", 10) || 20;
  const followExternal = q.followExternal === "true";

  if (!rawUrl) return { statusCode: 400, body: JSON.stringify({ error: "Missing ?url=" }) };

  let target;
  try {
    target = new URL(rawUrl);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid URL", details: e.message }) };
  }

  const result = {
    url: target.href,
    host: target.hostname,
    protocol: target.protocol,
    timestamp: new Date().toISOString(),
    summary: {},
    details: {},
  };

  // 1) Basic HTTP(S) fetch with redirects and timing
  let primaryResp = null;
  let primaryErr = null;
  const t0 = Date.now();
  try {
    primaryResp = await axios.get(target.href, {
      timeout: 15000,
      maxRedirects: 10,
      validateStatus: null,
      headers: { "User-Agent": "Netlify-DeepScan/1.0 (+https://example.local)" },
    });
  } catch (err) {
    primaryErr = err;
  }
  result.summary.responseTimeMs = Date.now() - t0;

  if (!primaryResp) {
    result.summary.reachable = false;
    result.details.fetchError = primaryErr?.message || "No response";
  } else {
    result.summary.reachable = primaryResp.status < 400;
    result.details.http = {
      status: primaryResp.status,
      redirectedTo: primaryResp.request?.res?.responseUrl || null,
      headers: primaryResp.headers,
      sizeBytes: calculateBodySize(primaryResp.data),
      contentType: primaryResp.headers["content-type"] || null,
      setCookie: primaryResp.headers["set-cookie"] || null,
    };
  }

  // 2) TLS certificate (if https)
  if (target.protocol === "https:") {
    try {
      const cert = await getCertificate(target.hostname);
      result.details.tls = {
        subject: cert.subject,
        issuer: cert.issuer,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        days_to_expiry: calcDaysToExpiry(cert.valid_to),
        valid_now: isCertValidNow(cert),
        raw: cert,
      };
    } catch (e) {
      result.details.tls_error = e.message;
    }
  } else {
    result.details.tls = { note: "Not HTTPS" };
  }

  // 3) Security headers
  const headers = primaryResp?.headers || {};
  result.details.securityHeaders = {
    strictTransportSecurity: headers["strict-transport-security"] || null,
    contentSecurityPolicy: headers["content-security-policy"] || null,
    xFrameOptions: headers["x-frame-options"] || null,
    xContentTypeOptions: headers["x-content-type-options"] || null,
    referrerPolicy: headers["referrer-policy"] || null,
    permissionsPolicy: headers["permissions-policy"] || headers["feature-policy"] || null,
    server: headers["server"] || headers["x-powered-by"] || null,
    accessControlAllowOrigin: headers["access-control-allow-origin"] || null,
  };

  // 4) Cookie analysis
  if (primaryResp?.headers?.["set-cookie"]) {
    result.details.cookies = analyzeCookies(primaryResp.headers["set-cookie"]);
  }

  // 5) Mixed content scan for HTTPS
  if (target.protocol === "https:" && primaryResp?.data) {
    result.details.mixedContent = findMixedContent(primaryResp.data, target.origin);
  }

  // 6) robots.txt, sitemap.xml, security.txt, favicon, manifest
  result.details.resources = {};
  result.details.resources.robots = await tryFetchText(new URL("/robots.txt", target.origin).href);
  result.details.resources.sitemap = await tryFetchText(new URL("/sitemap.xml", target.origin).href);
  result.details.resources.securitytxt = await tryFetchText(new URL("/.well-known/security.txt", target.origin).href);
  result.details.resources.favicon = await tryFetchStatus(new URL("/favicon.ico", target.origin).href);
  result.details.resources.manifest = await tryFetchText(new URL("/site.webmanifest", target.origin).href).catch(()=>({ok:false}));

  // 7) DNS records
  try {
    const [mx, txt, ns, a, soa] = await Promise.allSettled([
      dns.resolveMx(target.hostname).catch(()=>null),
      dns.resolveTxt(target.hostname).catch(()=>null),
      dns.resolveNs(target.hostname).catch(()=>null),
      dns.resolve4(target.hostname).catch(()=>null),
      dns.resolveSoa(target.hostname).catch(()=>null),
    ]);
    result.details.dns = {
      mx: mx.status === "fulfilled" ? mx.value : null,
      txt: txt.status === "fulfilled" ? txt.value : null,
      ns: ns.status === "fulfilled" ? ns.value : null,
      a: a.status === "fulfilled" ? a.value : null,
      soa: soa.status === "fulfilled" ? soa.value : null,
      has_spf: (txt.status === "fulfilled" && txt.value.flat().some(t=>t.includes("v=spf1"))) || false,
    };
  } catch (e) {
    result.details.dns_error = e.message;
  }

  // 8) TLS cipher and protocol info
  if (target.protocol === "https:") {
    try {
      const tlsInfo = await tryTlsInfo(target.hostname);
      result.details.tls_info = tlsInfo;
    } catch (e) {
      result.details.tls_info_error = e.message;
    }
  }

  // 9) Redirect chain analysis (followed by axios already but we can attempt manual)
  try {
    const chain = await getRedirectChain(target.href);
    result.details.redirectChain = chain;
  } catch (e) {
    result.details.redirectChainError = e.message;
  }

  // 10) Deep crawl (if requested)
  if (deep && primaryResp?.data) {
    result.details.deep = { crawled: 0, sample: [] };
    try {
      const $ = cheerio.load(primaryResp.data);
      const links = new Set();
      $("a[href]").each((i, el) => {
        const href = $(el).attr("href");
        if (!href) return;
        try {
          const u = new URL(href, target.origin);
          if (!followExternal && u.hostname !== target.hostname) return;
          if (u.protocol.startsWith("http")) links.add(u.href);
        } catch (e) {}
        if (links.size >= maxLinks) return false;
      });
      const list = Array.from(links).slice(0, maxLinks);
      result.details.deep.crawled = list.length;

      // parallel checks for sample links
      const checks = await Promise.all(list.map(async (link) => {
        try {
          const r = await axios.get(link, { timeout: 8000, maxRedirects: 5, validateStatus: null, headers: { "User-Agent": "Netlify-DeepScan/1.0" }});
          return {
            url: link,
            status: r.status,
            contentType: r.headers["content-type"] || null,
            hasCSP: !!r.headers["content-security-policy"],
            hasHSTS: !!r.headers["strict-transport-security"],
          };
        } catch (e) {
          return { url: link, error: e.message };
        }
      }));
      result.details.deep.sample = checks;
    } catch (e) {
      result.details.deep_error = e.message;
    }
  }

  // 11) Heuristic triage (basic scoring)
  result.summary.score = computeScore(result);

  return { statusCode: 200, body: JSON.stringify(result, null, 2) };
}

/* ---------------------------
   Helper functions
   --------------------------- */

function calculateBodySize(data) {
  try {
    if (!data) return 0;
    if (typeof data === "string") return Buffer.byteLength(data, "utf8");
    if (Buffer.isBuffer(data)) return data.length;
    return Buffer.byteLength(JSON.stringify(data), "utf8");
  } catch (e) { return null; }
}

async function tryFetchText(u) {
  try {
    const r = await axios.get(u, { timeout: 8000, maxRedirects: 5, validateStatus: null });
    return { ok: r.status >= 200 && r.status < 400, status: r.status, text: typeof r.data === "string" ? r.data : JSON.stringify(r.data).slice(0, 4000) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function tryFetchStatus(u) {
  try {
    const r = await axios.head(u, { timeout: 8000, maxRedirects: 5, validateStatus: null });
    return { ok: r.status >= 200 && r.status < 400, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function analyzeCookies(setCookieArray) {
  const arr = Array.isArray(setCookieArray) ? setCookieArray : [setCookieArray];
  return arr.map((c) => ({
    raw: c,
    secure: /;\s*secure/i.test(c),
    httpOnly: /;\s*httponly/i.test(c),
    sameSite: (c.match(/;\s*samesite=(\w+)/i) || [null, null])[1] || null,
  }));
}

function findMixedContent(html, origin) {
  try {
    const $ = cheerio.load(html || "");
    const insecure = [];
    $("img[src], script[src], link[href], iframe[src], source[src]").each((i, el) => {
      const attr = el.name === "link" ? $(el).attr("href") : $(el).attr("src");
      if (attr && attr.startsWith("http://")) insecure.push(attr);
    });
    return { insecureCount: insecure.length, examples: insecure.slice(0, 20) };
  } catch (e) {
    return { insecureCount: 0, error: e.message };
  }
}

function calcDaysToExpiry(valid_to) {
  try {
    const d = new Date(valid_to);
    const diff = d - new Date();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  } catch (e) { return null; }
}

function isCertValidNow(cert) {
  try {
    const from = new Date(cert.valid_from);
    const to = new Date(cert.valid_to);
    const now = new Date();
    return now >= from && now <= to;
  } catch (e) { return false; }
}

async function getCertificate(hostname) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, hostname, { servername: hostname, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      if (!cert || Object.keys(cert).length === 0) return reject(new Error("No certificate retrieved"));
      resolve(cert);
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

async function getRedirectChain(u) {
  // perform manual head requests following redirects up to 10 hops
  const chain = [];
  let current = u;
  for (let i=0;i<10;i++) {
    try {
      const r = await axios.head(current, { timeout: 8000, maxRedirects: 0, validateStatus: null });
      chain.push({ url: current, status: r.status, location: r.headers.location || null });
      if (r.status >= 300 && r.status < 400 && r.headers.location) {
        const next = new URL(r.headers.location, current).href;
        if (next === current) break;
        current = next;
        continue;
      }
      break;
    } catch (e) {
      chain.push({ url: current, error: e.message });
      break;
    }
  }
  return chain;
}

function computeScore(result) {
  // simple heuristic: start 100, subtract for missing best practices
  let score = 100;
  if (!result.summary.reachable) return 0;
  const headers = result.details.securityHeaders || {};
  if (!headers.strictTransportSecurity) score -= 20;
  if (!headers.contentSecurityPolicy) score -= 20;
  if (!headers.xFrameOptions) score -= 10;
  if (!headers.xContentTypeOptions) score -= 10;
  if (result.details.mixedContent && result.details.mixedContent.insecureCount > 0) score -= 15;
  if (result.details.tls && result.details.tls.days_to_expiry !== null && result.details.tls.days_to_expiry < 14) score -= 10;
  return Math.max(0, score);
}
