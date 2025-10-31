// =============================================
// 📚 API TỔNG HỢP BÁO + KIỂM TRA WEBSITE (VIỆT HÓA)
// =============================================

import axios from "axios";
import * as cheerio from "cheerio";
import dns from "dns/promises";
import tls from "tls";
import { URL } from "url";

// =================================================
// ✅ HÀM CHÍNH - PHÂN LUỒNG API
// =================================================
export async function handler(event) {
  const duongdan = event.path.replace("/.netlify/functions/api", "").replace("/", "");

  if (duongdan.startsWith("bao")) return layTinTuc(event);
  if (duongdan.startsWith("kiemtra")) return quetTrangWeb(event);

  return {
    statusCode: 404,
    body: JSON.stringify({ loi: "Không tìm thấy API. Dùng /bao hoặc /kiemtra" })
  };
}

// =================================================
// 📰 LẤY TIN TỨC MỚI NHẤT
// =================================================
async function layTinTuc(event) {
  const q = event.queryStringParameters || {};
  const nguon = (q.nguon || "vnexpress").toLowerCase();

  const nguonBao = {
    vnexpress: "https://vnexpress.net/",
    dantri: "https://dantri.com.vn/",
    "24h": "https://www.24h.com.vn/"
  };

  const url = nguonBao[nguon] || nguonBao.vnexpress;

  try {
    const { data } = await axios.get(url, {
      timeout: 10000,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "vi,en;q=0.9",
        "Referer": "https://www.google.com/"
      }
    });

    const $ = cheerio.load(data);
    const baiBao = [];

    if (nguon === "vnexpress") {
      $(".item-news a.thumb-art").each((i, el) => {
        if (i < 10) baiBao.push({
          tieuDe: $(el).attr("title") || $(el).text().trim(),
          lienKet: $(el).attr("href")
        });
      });
      // Phòng khi giao diện thay đổi
      if (baiBao.length === 0) {
        $("article a").each((i, el) => {
          if (i < 10) baiBao.push({
            tieuDe: $(el).text().trim(),
            lienKet: $(el).attr("href")
          });
        });
      }
    } else if (nguon === "dantri") {
      $(".news-item a").each((i, el) => {
        if (i < 10) baiBao.push({
          tieuDe: $(el).text().trim(),
          lienKet: "https://dantri.com.vn" + $(el).attr("href")
        });
      });
    } else if (nguon === "24h") {
      $(".cate-24h-foot-home a, .title_news_home a").each((i, el) => {
        if (i < 10) baiBao.push({
          tieuDe: $(el).text().trim(),
          lienKet: "https://www.24h.com.vn" + $(el).attr("href")
        });
      });
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        nguon,
        tongSo: baiBao.length,
        duLieu: baiBao.length ? baiBao : "Không lấy được dữ liệu (có thể bị chặn Cloudflare)"
      }, null, 2)
    };
  } catch (e) {
    return {
      statusCode: 500,
      body: JSON.stringify({ loi: "Không thể tải trang báo", chiTiet: e.message })
    };
  }
}

// =================================================
// 🧠 KIỂM TRA WEBSITE
// =================================================
async function quetTrangWeb(event) {
  const q = event.queryStringParameters || {};
  const rawUrl = q.url;
  const cheDo = (q.chedo || "nhanh").toLowerCase(); // nhanh hoặc chamsoc (chuyên sâu)

  if (!rawUrl) {
    return { statusCode: 400, body: JSON.stringify({ loi: "Thiếu tham số ?url=" }) };
  }

  let mucTieu;
  try {
    mucTieu = new URL(rawUrl);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ loi: "Địa chỉ URL không hợp lệ" }) };
  }

  const ketQua = {
    url: mucTieu.href,
    tenmien: mucTieu.hostname,
    chedo: cheDo,
    thoiGian: new Date().toISOString(),
    tomtat: {},
    chiTiet: {}
  };

  // 1️⃣ Kiểm tra phản hồi HTTP
  let phanHoi = null;
  try {
    const t0 = Date.now();
    phanHoi = await axios.get(mucTieu.href, {
      timeout: 15000,
      validateStatus: null,
      headers: { "User-Agent": "Mozilla/5.0 (Netlify-Scan)" }
    });
    ketQua.tomtAt = {
      trangThai: phanHoi.status,
      phanHoiMs: Date.now() - t0
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ loi: "Không thể truy cập website", chiTiet: e.message }) };
  }

  // 2️⃣ Kiểm tra chứng chỉ SSL (nếu HTTPS)
  if (mucTieu.protocol === "https:") {
    try {
      const cert = await layChungChi(mucTieu.hostname);
      ketQua.chiTiet.ssl = {
        nhaCungCap: cert.issuer,
        hopLeDen: cert.valid_to,
        hopLeTu: cert.valid_from
      };
    } catch (e) {
      ketQua.chiTiet.ssl = { loi: e.message };
    }
  }

  // 3️⃣ Kiểm tra header bảo mật
  const h = phanHoi.headers || {};
  ketQua.chiTiet.baoMat = {
    HSTS: !!h["strict-transport-security"],
    CSP: !!h["content-security-policy"],
    XFrame: !!h["x-frame-options"],
    XContentType: !!h["x-content-type-options"],
    CORS: !!h["access-control-allow-origin"]
  };

  // 4️⃣ DNS cơ bản
  try {
    const [mx, ns, txt] = await Promise.all([
      dns.resolveMx(mucTieu.hostname).catch(() => null),
      dns.resolveNs(mucTieu.hostname).catch(() => null),
      dns.resolveTxt(mucTieu.hostname).catch(() => null)
    ]);
    ketQua.chiTiet.dns = { mx, ns, txt };
  } catch (e) {
    ketQua.chiTiet.dns = { loi: e.message };
  }

  // 5️⃣ Nếu quét "chuyên sâu" thì kiểm tra link con trong trang
  if (cheDo === "chamsoc" && phanHoi.data) {
    const $ = cheerio.load(phanHoi.data);
    const linkCon = new Set();
    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      try {
        const u = new URL(href, mucTieu.origin);
        if (u.hostname === mucTieu.hostname) linkCon.add(u.href);
      } catch {}
    });

    const arr = Array.from(linkCon).slice(0, 20);
    const ketQuaCon = await Promise.all(arr.map(async (u) => {
      try {
        const r = await axios.head(u, { timeout: 5000, validateStatus: null });
        return { url: u, trangThai: r.status };
      } catch (e) {
        return { url: u, loi: e.message };
      }
    }));
    ketQua.chiTiet.quetSau = { soLuong: arr.length, ketQuaCon };
  }

  return {
    statusCode: 200,
    body: JSON.stringify(ketQua, null, 2)
  };
}

// =================================================
// ⚙️ HÀM PHỤ TRỢ
// =================================================
async function layChungChi(host) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, host, { servername: host, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      if (!cert || Object.keys(cert).length === 0) return reject(new Error("Không lấy được chứng chỉ SSL"));
      resolve(cert);
    });
    socket.on("error", reject);
    socket.on("timeout", () => reject(new Error("Hết thời gian kết nối SSL")));
  });
}
