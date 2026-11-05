// ============================================================
// Cloudflare Worker —— 流量查询 + 后台管理
// ============================================================
// 环境变量：
//   SYNC_TOKEN       —— 脚本 POST /sync 的鉴权 token
//   ADMIN_PASSWORD   —— 后台管理登录密码
//   CAPTCHA_SECRET   —— 验证码签名密钥（随便一串随机字符）
//
// KV 绑定：
//   SS_USERS         —— 存储用户数据
//
// 路由：
//   POST /sync       —— 脚本上传用户数据（需 SYNC_TOKEN）
//   GET  /captcha    —— 生成图形验证码 SVG
//   GET  /admin      —— 后台登录页 / 用户列表（需密码 + 验证码）
//   GET  /?key=xxx   —— 查询单个用户
// ============================================================

const CACHE_TTL = 300;
const ADMIN_COOKIE = "admin_auth";
const CAPTCHA_COOKIE = "captcha_token";
const PAGE_SIZE = 10;

const LOGO_URL = "https://cdn.simpleicons.org/cloudflare/4f46e5";
const FAVICON = `<link rel="icon" type="image/svg+xml" href="${LOGO_URL}">`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 路由 1：POST /sync
    if (request.method === "POST" && url.pathname === "/sync") {
      const auth = request.headers.get("Authorization") || "";
      if (auth !== `Bearer ${env.SYNC_TOKEN}`) {
        return new Response("unauthorized", { status: 401 });
      }

      let payload;
      try {
        payload = await request.json();
      } catch (e) {
        return new Response("bad json", { status: 400 });
      }

      const users = payload.users || [];
      const ts = Math.floor(Date.now() / 1000);

      const BATCH = 50;
      for (let i = 0; i < users.length; i += BATCH) {
        await Promise.all(users.slice(i, i + BATCH).map(async (u) => {
          const value = JSON.stringify({
            name:   u.name,
            used:   u.used   || 0,
            limit:  u.limit  || 0,
            expire: u.expire || 0,
            traffic_expire: u.traffic_expire || 0,
            status: u.status || "",
            port:   u.port   || 0,
            updated_at: ts,
          });
          await env.SS_USERS.put(`user:${u.key}`, value);
        }));
      }

      try {
        const currentKeys = new Set(users.map(u => u.key));
        const list = await env.SS_USERS.list({ prefix: "user:" });
        await Promise.all(list.keys.map(async (k) => {
          const kKey = k.name.slice("user:".length);
          if (!currentKeys.has(kKey)) {
            await env.SS_USERS.delete(k.name);
          }
        }));
      } catch (e) {}

      await env.SS_USERS.put("meta:last_sync", String(ts));

      return new Response(JSON.stringify({ ok: true, count: users.length }), {
        headers: { "content-type": "application/json" },
      });
    }

    // 路由 2：GET /captcha
    if (url.pathname === "/captcha") {
      return await generateCaptcha(env);
    }

    // 路由 3：/admin
    if (url.pathname === "/admin" || url.searchParams.has("admin")) {
      if (request.method === "POST") {
        const form = await request.formData();
        const pwd = String(form.get("password") || "");
        const captchaInput = String(form.get("captcha") || "").trim().toUpperCase();

        const cookie = request.headers.get("Cookie") || "";
        const captchaToken = getCookie(cookie, CAPTCHA_COOKIE);
        const captchaAnswer = await verifyCaptchaToken(captchaToken, env);

        if (!captchaAnswer || captchaAnswer !== captchaInput) {
          return adminLoginPage("验证码错误，请重试", env);
        }

        if (pwd !== env.ADMIN_PASSWORD) {
          return adminLoginPage("密码错误，请重试", env);
        }

        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/admin",
            "Set-Cookie": `${ADMIN_COOKIE}=${encodeURIComponent(env.ADMIN_PASSWORD)}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax`,
          },
        });
      }

      const cookie = request.headers.get("Cookie") || "";
      const token = getCookie(cookie, ADMIN_COOKIE);
      if (token !== env.ADMIN_PASSWORD) {
        return adminLoginPage("", env);
      }

      return await adminDashboard(env);
    }

    // 路由 4：GET / 或 /query
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/query")) {
      const key = url.searchParams.get("key");
      const embed = url.searchParams.get("embed") === "1";

      if (!key) {
        return htmlPage("查询流量", `
          <form class="key-form" onsubmit="event.preventDefault(); const v=this.key.value.trim(); if(v) location.href='/?key='+encodeURIComponent(v);">
            <div class="key-input-wrap">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="7"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <input name="key" type="text" placeholder="请输入你的 key" autocomplete="off" autofocus required>
            </div>
            <button type="submit">查询</button>
          </form>
          <p class="hint" style="text-align:center;margin-top:.75rem">
            也可以直接访问 <code>?key=你的key</code>
          </p>
        `, embed);
      }

      const raw = await env.SS_USERS.get(`user:${key}`, { cacheTtl: CACHE_TTL });
      if (!raw) {
        return htmlPage("未找到", `
          <div class="empty">
            <div class="empty-icon">🚫</div>
            <p>key 无效，或尚未同步</p>
            <p class="hint">请确认 key 是否正确，或等待脚本同步完成</p>
          </div>
        `, embed);
      }

      const u = JSON.parse(raw);
      return htmlPage(u.name, renderUser(u), embed);
    }

    return new Response("not found", { status: 404 });
  }
};

// ============================================================
// 验证码
// ============================================================

async function generateCaptcha(env) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  const rand = crypto.getRandomValues(new Uint8Array(4));
  for (let i = 0; i < 4; i++) {
    code += chars[rand[i] % chars.length];
  }

  const exp = Math.floor(Date.now() / 1000) + 300;
  const payload = `${code}.${exp}`;
  const sig = await hmacSign(payload, env.CAPTCHA_SECRET || "default_secret");
  const token = `${payload}.${sig}`;

  const svg = makeCaptchaSvg(code);

  return new Response(svg, {
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Set-Cookie": `${CAPTCHA_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=300; SameSite=Lax`,
    },
  });
}

async function verifyCaptchaToken(token, env) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [code, exp, sig] = parts;

  const payload = `${code}.${exp}`;
  const expected = await hmacSign(payload, env.CAPTCHA_SECRET || "default_secret");
  if (sig !== expected) return null;

  if (Number(exp) < Math.floor(Date.now() / 1000)) return null;

  return code;
}

async function hmacSign(text, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(text));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function makeCaptchaSvg(code) {
  const W = 120, H = 44;
  const colors = ["#4f46e5", "#7c3aed", "#ec4899", "#0ea5e9", "#16a34a"];
  let chars = "";
  const charW = W / (code.length + 1);

  for (let i = 0; i < code.length; i++) {
    const x = charW * (i + 0.5) + charW * 0.5;
    const y = H / 2 + 8;
    const rot = (Math.random() * 30 - 15).toFixed(1);
    const color = colors[Math.floor(Math.random() * colors.length)];
    const size = (24 + Math.random() * 6).toFixed(0);
    chars += `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" font-size="${size}" font-weight="700"
      font-family="Arial,sans-serif" fill="${color}"
      transform="rotate(${rot} ${x.toFixed(1)} ${y.toFixed(1)})"
      text-anchor="middle">${code[i]}</text>`;
  }

  let lines = "";
  for (let i = 0; i < 3; i++) {
    const x1 = Math.random() * W, y1 = Math.random() * H;
    const x2 = Math.random() * W, y2 = Math.random() * H;
    const c = colors[Math.floor(Math.random() * colors.length)];
    lines += `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"
      stroke="${c}" stroke-width="1" opacity="0.4"/>`;
  }

  let dots = "";
  for (let i = 0; i < 25; i++) {
    const cx = Math.random() * W, cy = Math.random() * H;
    const c = colors[Math.floor(Math.random() * colors.length)];
    dots += `<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="1" fill="${c}" opacity="0.5"/>`;
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
    <rect width="${W}" height="${H}" fill="#f9fafb" rx="8"/>
    ${lines}${dots}${chars}
  </svg>`;
}

function getCookie(cookieStr, name) {
  const m = cookieStr.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : "";
}

// ============================================================
// 登录页
// ============================================================

function adminLoginPage(error = "", env) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>后台登录</title>
${FAVICON}
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
       background:linear-gradient(135deg,#eef2ff 0%,#f7f8fa 40%,#faf5ff 100%);
       color:#1f2937;min-height:100vh;
       display:flex;justify-content:center;align-items:center;padding:1.5rem;
       position:relative;overflow:hidden}
  body::before,body::after{content:"";position:absolute;border-radius:50%;filter:blur(60px);opacity:.5;z-index:0}
  body::before{width:340px;height:340px;background:#c7d2fe;top:-100px;left:-80px}
  body::after{width:300px;height:300px;background:#fbcfe8;bottom:-100px;right:-80px}

  .card{position:relative;z-index:1;background:#fff;border-radius:24px;
        max-width:400px;width:100%;overflow:hidden;
        box-shadow:0 20px 60px rgba(79,70,229,.16),0 4px 12px rgba(0,0,0,.05)}
  .head{padding:2rem 2rem 1.5rem;text-align:center;
        background:linear-gradient(135deg,#4f46e5,#7c3aed 55%,#ec4899);color:#fff;
        position:relative;overflow:hidden}
  .head::after{content:"";position:absolute;width:200px;height:200px;
        background:rgba(255,255,255,.10);border-radius:50%;top:-90px;right:-60px}
  .logo{width:56px;height:56px;margin:0 auto .9rem;border-radius:16px;
        display:flex;align-items:center;justify-content:center;
        background:rgba(255,255,255,.20);backdrop-filter:blur(4px);
        box-shadow:0 4px 14px rgba(0,0,0,.12);overflow:hidden}
  .logo img{width:100%;height:100%;object-fit:contain;display:block;padding:10px;filter:brightness(0) invert(1)}
  .head h1{font-size:1.15rem;font-weight:700;letter-spacing:.02em}
  .head p{font-size:.78rem;opacity:.85;margin-top:.35rem}

  .body{padding:1.75rem 1.75rem 2rem}
  .field{margin-bottom:1.1rem}
  label{display:block;font-size:.78rem;color:#6b7280;margin-bottom:.5rem;font-weight:600;
        letter-spacing:.02em}
  .input-wrap{position:relative}
  .input-wrap svg{position:absolute;left:.9rem;top:50%;transform:translateY(-50%);
        width:16px;height:16px;stroke:#9ca3af;pointer-events:none;transition:stroke .2s}
  input[type=password],input[type=text]{
        width:100%;padding:.8rem 1rem .8rem 2.6rem;
        border:1.5px solid #e5e7eb;border-radius:12px;
        font-size:.95rem;outline:none;font-family:inherit;
        background:#fafafa;transition:all .2s}
  input::placeholder{color:#c4c8d0}
  input:focus{border-color:#4f46e5;background:#fff;
        box-shadow:0 0 0 4px rgba(79,70,229,.10)}
  .input-wrap:focus-within svg{stroke:#4f46e5}

  .captcha-row{display:flex;gap:.65rem;align-items:stretch}
  .captcha-row .input-wrap{flex:1}
  .captcha-img{height:48px;border-radius:12px;cursor:pointer;
        border:1.5px solid #e5e7eb;background:#f9fafb;flex-shrink:0;display:block;
        transition:border-color .2s}
  .captcha-img:hover{border-color:#4f46e5}

  button{width:100%;margin-top:.6rem;padding:.9rem;border:none;border-radius:12px;
         background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;
         font-size:.95rem;font-weight:600;cursor:pointer;font-family:inherit;
         transition:transform .1s,box-shadow .2s;letter-spacing:.02em}
  button:hover{box-shadow:0 8px 24px rgba(79,70,229,.40)}
  button:active{transform:scale(.98)}

  .error{margin-top:1rem;padding:.7rem .95rem;background:#fee2e2;color:#dc2626;
         border-radius:10px;font-size:.82rem;text-align:center;
         display:flex;align-items:center;justify-content:center;gap:.4rem;
         border:1px solid #fecaca}
  .hint{margin-top:.5rem;font-size:.72rem;color:#9ca3af;text-align:center}
  .footer{margin-top:1.5rem;text-align:center;font-size:.72rem;color:#c4c8d0}

  @media(max-width:480px){
    body{padding:1rem}
    .card{border-radius:20px}
    .head{padding:1.6rem 1.5rem 1.25rem}
    .logo{width:48px;height:48px}
    .head h1{font-size:1.05rem}
    .body{padding:1.5rem 1.35rem 1.75rem}
    input[type=password],input[type=text]{font-size:16px}
  }
</style></head><body>
<div class="card">
  <div class="head">
    <div class="logo"><img src="${LOGO_URL}" alt="logo"></div>
    <h1>后台管理</h1>
    <p>请输入管理员密码和验证码</p>
  </div>
  <div class="body">
    <form method="POST" autocomplete="off">
      <div class="field">
        <label>管理员密码</label>
        <div class="input-wrap">
          <input type="password" name="password" required autofocus placeholder="输入密码">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
      </div>
      <div class="field">
        <label>验证码</label>
        <div class="captcha-row">
          <div class="input-wrap">
            <input type="text" name="captcha" required maxlength="4" autocomplete="off"
                   placeholder="4 位字符" style="text-transform:uppercase">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M9 12l2 2 4-4"/>
              <path d="M21 12c0 4.97-4.03 9-9 9s-9-4.03-9-9 4.03-9 9-9c1.66 0 3.22.45 4.56 1.24"/>
            </svg>
          </div>
          <img class="captcha-img" id="captchaImg" src="/captcha" alt="点击刷新"
               onclick="this.src='/captcha?t='+Date.now()">
        </div>
        <div class="hint">看不清？点击图片刷新</div>
      </div>
      <button type="submit">登录后台</button>
    </form>
    ${error ? `<div class="error">
      <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor"
           stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      ${escapeHtml(error)}
    </div>` : ""}
    <div class="footer">Cloudflare Worker · 流量管理后台</div>
  </div>
</div>
<script>
  document.getElementById('captchaImg').src = '/captcha?t=' + Date.now();
</script>
</body></html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

// ============================================================
// 后台：用户列表（前端分页）
// ============================================================

async function adminDashboard(env) {
  const list = await env.SS_USERS.list({ prefix: "user:" });
  const users = [];

  const BATCH = 50;
  for (let i = 0; i < list.keys.length; i += BATCH) {
    const batch = list.keys.slice(i, i + BATCH);
    const values = await Promise.all(
      batch.map(k => env.SS_USERS.get(k.name, { cacheTtl: 60 }))
    );
    values.forEach((raw, idx) => {
      if (!raw) return;
      try {
        const u = JSON.parse(raw);
        u.key = batch[idx].name.slice("user:".length);
        users.push(u);
      } catch (e) {}
    });
  }

  users.sort((a, b) => (a.expire || Infinity) - (b.expire || Infinity));

  const lastSync = await env.SS_USERS.get("meta:last_sync", { cacheTtl: 60 });
  const now = Math.floor(Date.now() / 1000);

  const usersData = users.map(u => {
    const limit = u.limit || 0;
    const used  = u.used  || 0;
    const expire = u.expire || 0;
    const trafficExpire = u.traffic_expire || 0;

    let statusText = "正常", statusClass = "ok";
    if (u.status === "流量超限") { statusText = "流量超限"; statusClass = "warn"; }
    else if (u.status === "已到期") { statusText = "已到期"; statusClass = "bad"; }
    else if (u.status && u.status !== "正常") { statusText = u.status; statusClass = "bad"; }

    const remainClass = !expire ? "ok"
                      : (expire - now <= 0 ? "bad"
                      : (expire - now < 7*86400 ? "warn" : "ok"));
    const trafficRemainClass = !trafficExpire ? "ok"
                      : (trafficExpire - now <= 0 ? "bad"
                      : (trafficExpire - now < 7*86400 ? "warn" : "ok"));

    return {
      key: u.key,
      name: u.name || "",
      used,
      limit,
      usedText: human(used),
      limitText: limit > 0 ? human(limit) : "不限",
      percent: limit > 0 ? Math.min(used / limit * 100, 100) : 0,
      statusText,
      statusClass,
      expireText: expire ? fmtTs(expire) : "永久",
      remainText: expire ? remain(expire) : "永久",
      remainClass,
      trafficExpireText: trafficExpire ? fmtTs(trafficExpire) : "—",
      trafficRemainText: trafficExpire ? remain(trafficExpire) : "—",
      trafficRemainClass,
      updatedText: fmtTs(u.updated_at || 0),
    };
  });

  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>用户列表 · 后台</title>
${FAVICON}
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
       background:linear-gradient(135deg,#eef2ff 0%,#f7f8fa 40%,#faf5ff 100%);
       color:#1f2937;min-height:100vh;padding:2rem 1rem}
  .wrap{max-width:1400px;margin:0 auto}
  .card{background:#fff;border-radius:20px;
        box-shadow:0 10px 40px rgba(79,70,229,.10),0 2px 8px rgba(0,0,0,.04);overflow:hidden}
  .head{display:flex;align-items:center;justify-content:space-between;
        padding:1.1rem 1.75rem;gap:.75rem;
        background:linear-gradient(135deg,#4f46e5,#7c3aed 60%,#ec4899);color:#fff}
  .head-left{display:flex;align-items:center;gap:.7rem;min-width:0}
  .logo{width:32px;height:32px;flex-shrink:0;display:flex;align-items:center;
        justify-content:center;background:rgba(255,255,255,.18);border-radius:9px;
        overflow:hidden}
  .logo img{width:100%;height:100%;object-fit:contain;display:block;padding:6px;filter:brightness(0) invert(1)}
  .head-title{font-size:.95rem;font-weight:700;white-space:nowrap}
  .head-title small{display:block;font-size:.7rem;font-weight:400;opacity:.85;margin-top:.1rem}
  .head-right{font-size:.78rem;opacity:.9;white-space:nowrap;
        overflow:hidden;text-overflow:ellipsis}
  .toolbar{padding:1rem 1.75rem;border-bottom:1px solid #f3f4f6;
           display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem}
  .count{font-size:.85rem;color:#6b7280}
  .count b{color:#4f46e5}

  .table-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
  table{width:100%;border-collapse:collapse;table-layout:auto;min-width:760px}
  th,td{padding:.85rem 1rem;text-align:left;font-size:.85rem;
        border-bottom:1px solid #f3f4f6;vertical-align:middle;white-space:nowrap}
  th{background:#fafafa;color:#6b7280;font-weight:600;font-size:.78rem;
     text-transform:uppercase;letter-spacing:.04em;position:sticky;top:0;z-index:1}
  tr:hover td{background:#fafbff}
  tr.user-row{cursor:pointer}
  tr.user-row:active td{background:#eef2ff}
  td.key-cell code{background:#f3f4f6;padding:.2rem .5rem;border-radius:6px;
                   font-size:.78rem;color:#4f46e5;word-break:break-all;white-space:normal}
  td.name-cell{font-weight:600;color:#111827}

  .mini-bar{background:#f3f4f6;border-radius:999px;height:6px;overflow:hidden;
            width:140px;margin-bottom:.25rem}
  .mini-bar>i{display:block;height:100%;border-radius:999px;
              background:linear-gradient(90deg,#4f46e5,#7c3aed)}
  .mini-bar.warn>i{background:linear-gradient(90deg,#f59e0b,#f97316)}
  .mini-bar.danger>i{background:linear-gradient(90deg,#ef4444,#dc2626)}

  .mini-text{font-size:.72rem;color:#9ca3af}
  .status-pill{font-size:.7rem;padding:.2rem .6rem;border-radius:999px;font-weight:600;white-space:nowrap}
  .status-pill.ok{background:#dcfce7;color:#16a34a}
  .status-pill.warn{background:#fef3c7;color:#d97706}
  .status-pill.bad{background:#fee2e2;color:#dc2626}
  .ok{color:#16a34a !important} .warn{color:#d97706 !important} .bad{color:#dc2626 !important}
  .empty{padding:3rem 2rem;text-align:center;color:#9ca3af;font-size:.9rem}
  .empty-icon{font-size:2.5rem;margin-bottom:.75rem}

  .pager{display:flex;align-items:center;justify-content:center;
         gap:.4rem;flex-wrap:wrap;padding:1rem 1.25rem 1.25rem;
         border-top:1px solid #f3f4f6}
  .pager button{border:1px solid #e5e7eb;background:#fff;color:#374151;
         min-width:36px;height:36px;padding:0 .7rem;border-radius:10px;
         font-size:.82rem;font-weight:600;cursor:pointer;font-family:inherit;
         transition:all .15s;-webkit-tap-highlight-color:transparent}
  .pager button:hover:not(:disabled){border-color:#4f46e5;color:#4f46e5;background:#f5f3ff}
  .pager button:disabled{opacity:.45;cursor:not-allowed}
  .pager button.active{background:linear-gradient(135deg,#4f46e5,#7c3aed);
         color:#fff;border-color:transparent;
         box-shadow:0 4px 12px rgba(79,70,229,.35)}
  .pager .dots{color:#9ca3af;font-size:.85rem;padding:0 .25rem}
  .pager-info{font-size:.78rem;color:#9ca3af;text-align:center;
         padding:0 1.25rem 1rem}

  .modal-mask{
    position:fixed;inset:0;background:rgba(17,24,39,.55);
    display:none;align-items:center;justify-content:center;
    padding:2rem;z-index:50;backdrop-filter:blur(3px);
  }
  .modal-mask.show{display:flex}
  .modal-box{
    background:#fff;border-radius:16px;overflow:hidden;
    width:min(480px,100%);height:auto;max-height:82vh;
    display:flex;flex-direction:column;
    box-shadow:0 24px 70px rgba(0,0,0,.32);
  }
  .modal-head{
    display:flex;align-items:center;justify-content:space-between;
    padding:.9rem 1.15rem;flex-shrink:0;
    background:linear-gradient(135deg,#4f46e5,#7c3aed 60%,#ec4899);color:#fff;
    font-size:.9rem;font-weight:700;
  }
  .modal-close{
    border:none;background:rgba(255,255,255,.18);color:#fff;
    width:30px;height:30px;border-radius:8px;cursor:pointer;
    font-size:1.2rem;line-height:1;display:flex;align-items:center;justify-content:center;
    -webkit-tap-highlight-color:transparent;
  }
  .modal-close:hover{background:rgba(255,255,255,.32)}
  .modal-box iframe{
    flex:1;width:100%;border:none;background:#fff;min-height:440px;
  }
  body.modal-open{overflow:hidden}

  @media(max-width:900px){
    body{padding:1rem .5rem}
    .head{padding:1rem 1.15rem}
    .toolbar{padding:.75rem 1.15rem}
    th,td{padding:.65rem .7rem;font-size:.78rem}
    .mini-bar{width:100px}
    .head-title small{display:none}
    .head-right{font-size:.7rem}
  }
  @media(max-width:640px){
    body{padding:0}
    .card{border-radius:0;box-shadow:none;min-height:100vh}
    .head{padding:.9rem 1rem;border-radius:0}
    .head-right{display:none}
    .toolbar{padding:.65rem 1rem}
    .modal-mask{padding:0}
    .modal-box{width:100%;height:100vh;max-height:none;border-radius:0}
    .modal-head{padding:.85rem 1rem}
    .pager button{min-width:34px;height:34px;font-size:.78rem}
  }
</style></head><body>
<div class="wrap">
  <div class="card">
    <div class="head">
      <div class="head-left">
        <div class="logo"><img src="${LOGO_URL}" alt="logo"></div>
        <div class="head-title">用户列表<small>后台管理</small></div>
      </div>
      <div class="head-right">上次同步：${lastSync ? fmtTs(Number(lastSync)) : "-"}</div>
    </div>
    <div class="toolbar">
      <div class="count">共 <b>${users.length}</b> 个用户</div>
      <div class="count">每页 <b>${PAGE_SIZE}</b> 条</div>
    </div>
    ${users.length === 0 ? `
      <div class="empty"><div class="empty-icon">📭</div><p>暂无用户数据，等待脚本同步</p></div>
    ` : `
      <div class="table-scroll">
        <table>
          <thead><tr>
            <th>Key</th><th>用户名</th><th>流量</th><th>流量周期</th><th>状态</th><th>账号到期</th><th>更新时间</th>
          </tr></thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
      <div class="pager" id="pager"></div>
      <div class="pager-info" id="pagerInfo"></div>
    `}
  </div>
</div>

<div class="modal-mask" id="modalMask">
  <div class="modal-box">
    <div class="modal-head">
      <span id="modalTitle">用户详情</span>
      <button class="modal-close" id="modalClose" type="button">×</button>
    </div>
    <iframe id="modalFrame" src="about:blank"></iframe>
  </div>
</div>

<script>
(function(){
  const USERS = ${JSON.stringify(usersData)};
  const PAGE_SIZE = ${PAGE_SIZE};
  let page = 1;
  const totalPages = Math.max(1, Math.ceil(USERS.length / PAGE_SIZE));

  const tbody    = document.getElementById('tbody');
  const pager    = document.getElementById('pager');
  const pagerInfo= document.getElementById('pagerInfo');

  function esc(s){
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }

  function renderRows(){
    const start = (page - 1) * PAGE_SIZE;
    const slice = USERS.slice(start, start + PAGE_SIZE);
    tbody.innerHTML = slice.map(u => {
      const barClass = u.limit === 0 ? ''
                     : (u.percent >= 90 ? 'danger' : u.percent >= 70 ? 'warn' : '');
      return \`
        <tr class="user-row" data-key="\${esc(u.key)}">
          <td class="key-cell"><code>\${esc(u.key)}</code></td>
          <td class="name-cell">\${esc(u.name)}</td>
          <td>
            <div class="mini-bar \${barClass}"><i style="width:\${u.percent.toFixed(1)}%"></i></div>
            <div class="mini-text">\${esc(u.usedText)} / \${esc(u.limitText)}</div>
          </td>
          <td>
            <div>\${esc(u.trafficExpireText)}</div>
            <div class="mini-text \${u.trafficRemainClass}">\${esc(u.trafficRemainText)}</div>
          </td>
          <td><span class="status-pill \${u.statusClass}">\${esc(u.statusText)}</span></td>
          <td>
            <div>\${esc(u.expireText)}</div>
            <div class="mini-text \${u.remainClass}">\${esc(u.remainText)}</div>
          </td>
          <td class="mini-text">\${esc(u.updatedText)}</td>
        </tr>
      \`;
    }).join('');

    tbody.querySelectorAll('tr.user-row').forEach(tr => {
      tr.addEventListener('click', () => openModal(tr.dataset.key));
    });
  }

  function renderPager(){
    const parts = [];
    const add = (label, p, opts = {}) => {
      parts.push(\`<button data-page="\${p}" \${opts.disabled ? 'disabled' : ''} \${opts.active ? 'class="active"' : ''}>\${label}</button>\`);
    };

    add('‹', page - 1, { disabled: page === 1 });

    const range = [];
    const push = p => { if (p >= 1 && p <= totalPages && !range.includes(p)) range.push(p); };
    push(1);
    for (let p = page - 2; p <= page + 2; p++) push(p);
    push(totalPages);
    range.sort((a,b) => a-b);

    let prev = 0;
    for (const p of range) {
      if (p - prev > 1) parts.push('<span class="dots">…</span>');
      add(String(p), p, { active: p === page });
      prev = p;
    }

    add('›', page + 1, { disabled: page === totalPages });

    pager.innerHTML = parts.join('');
    pager.querySelectorAll('button[data-page]').forEach(btn => {
      btn.addEventListener('click', () => {
        const p = Number(btn.dataset.page);
        if (!p || p < 1 || p > totalPages || p === page) return;
        page = p;
        renderRows();
        renderPager();
        renderInfo();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
    });
  }

  function renderInfo(){
    const total = USERS.length;
    const start = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
    const end   = Math.min(page * PAGE_SIZE, total);
    pagerInfo.textContent = \`显示 \${start}-\${end} / 共 \${total} 条 · 第 \${page}/\${totalPages} 页\`;
  }

  const mask  = document.getElementById('modalMask');
  const frame = document.getElementById('modalFrame');
  const title = document.getElementById('modalTitle');

  function openModal(key){
    frame.src = '/?key=' + encodeURIComponent(key) + '&embed=1';
    title.textContent = '详情 · ' + key;
    mask.classList.add('show');
    document.body.classList.add('modal-open');
  }
  function closeModal(){
    mask.classList.remove('show');
    document.body.classList.remove('modal-open');
    frame.src = 'about:blank';
  }
  document.getElementById('modalClose').addEventListener('click', e => {
    e.stopPropagation(); closeModal();
  });
  mask.addEventListener('click', e => { if (e.target === mask) closeModal(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && mask.classList.contains('show')) closeModal();
  });

  if (USERS.length > 0){
    renderRows();
    renderPager();
    renderInfo();
  }
})();
</script>
</body></html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

// ============================================================
// 工具函数
// ============================================================

function fmtTs(ts) {
  if (!ts) return "-";
  const d = new Date((ts + 8 * 3600) * 1000);
  const p = x => String(x).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())}\u00A0${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function remain(ts) {
  const diff = ts - Math.floor(Date.now()/1000);
  if (diff <= 0) return "已到期";
  const d = Math.floor(diff / 86400);
  const h = Math.floor((diff % 86400) / 3600);
  const m = Math.floor((diff % 3600) / 60);
  if (d > 0) return `${d}天${h}小时`;
  if (h > 0) return `${h}小时${m}分钟`;
  return `${m}分钟`;
}

function renderUser(u) {
  const limit  = u.limit  || 0;
  const used   = u.used   || 0;
  const expire = u.expire || 0;
  const trafficExpire = u.traffic_expire || 0;

  const usedText  = human(used);
  const limitText = limit > 0 ? human(limit) : "不限";
  const remainBytes = limit > 0 ? Math.max(limit - used, 0) : 0;
  const percent   = limit > 0 ? Math.min(used / limit * 100, 100) : 0;

  const expireText = expire ? fmtTs(expire) : "永久";
  const remainText = expire ? remain(expire) : "永久";

  const trafficExpireText = trafficExpire ? fmtTs(trafficExpire) : "—";
  const trafficRemainText = trafficExpire ? remain(trafficExpire) : "—";

  let statusText = "正常", statusClass = "ok";
  if (u.status === "流量超限") { statusText = "流量超限"; statusClass = "warn"; }
  else if (u.status === "已到期") { statusText = "已到期"; statusClass = "bad"; }
  else if (u.status && u.status !== "正常") { statusText = u.status; statusClass = "bad"; }

  const now = Math.floor(Date.now()/1000);
  const remainClass = !expire ? "ok"
                    : (expire - now <= 0 ? "bad"
                    : (expire - now < 7*86400 ? "warn" : "ok"));
  const trafficRemainClass = !trafficExpire ? "ok"
                    : (trafficExpire - now <= 0 ? "bad"
                    : (trafficExpire - now < 7*86400 ? "warn" : "ok"));

  const barClass = limit === 0 ? ""
                 : (percent >= 90 ? "danger" : percent >= 70 ? "warn" : "");

  return `
    <div class="status-badge ${statusClass}">
      <span class="dot"></span>${statusText}
    </div>

    <div class="hero">
      <div class="hero-label">已用流量</div>
      <div class="hero-value">${usedText}</div>
      <div class="hero-sub">
        <span>总额度 ${limitText}</span>
        ${limit > 0 ? `<span class="hero-remain">剩余 ${human(remainBytes)}</span>` : ""}
      </div>
      <div class="hero-bar ${barClass}">
        <i style="width:${percent.toFixed(1)}%"></i>
      </div>
      <div class="hero-percent">${limit > 0 ? percent.toFixed(1) + "%" : "不限流量"}</div>
    </div>

    <div class="info-grid">
      <div class="info-item">
        <div class="info-icon">📅</div>
        <div class="info-body">
          <div class="info-label">流量周期到期</div>
          <div class="info-value">${trafficExpireText}</div>
          <div class="info-extra ${trafficRemainClass}">${trafficRemainText}</div>
        </div>
      </div>
      <div class="info-item">
        <div class="info-icon">⏰</div>
        <div class="info-body">
          <div class="info-label">账号到期</div>
          <div class="info-value">${expireText}</div>
          <div class="info-extra ${remainClass}">${remainText}</div>
        </div>
      </div>
    </div>

    <div class="updated">
      <span class="pulse"></span>数据更新于 ${fmtTs(u.updated_at || 0)}
    </div>
  `;
}

function human(n) {
  const units = ["B","KB","MB","GB","TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(2) + " " + units[i];
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

function htmlPage(title, body, embed = false) {
  const bodyClass = embed ? "embed" : "";
  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
${FAVICON}
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
       background:linear-gradient(135deg,#eef2ff 0%,#f7f8fa 40%,#faf5ff 100%);
       color:#1f2937;min-height:100vh;padding:2rem 1rem;
       display:flex;justify-content:center;align-items:flex-start}

  .card{background:#fff;border-radius:24px;max-width:460px;width:100%;overflow:hidden;
        box-shadow:0 20px 60px rgba(79,70,229,.14),0 4px 12px rgba(0,0,0,.04);
        position:relative}
  .head{display:flex;align-items:center;gap:.75rem;padding:1.15rem 1.75rem;
        background:linear-gradient(135deg,#4f46e5,#7c3aed 55%,#ec4899);color:#fff;
        position:relative;overflow:hidden}
  .head::after{content:"";position:absolute;width:160px;height:160px;
        background:rgba(255,255,255,.10);border-radius:50%;top:-80px;right:-40px}
  .logo{width:34px;height:34px;flex-shrink:0;border-radius:10px;
        display:flex;align-items:center;justify-content:center;
        background:rgba(255,255,255,.20);position:relative;z-index:1;
        overflow:hidden}
  .logo img{width:100%;height:100%;object-fit:contain;display:block;padding:6px;filter:brightness(0) invert(1)}
  .head-title{font-size:.95rem;font-weight:700;position:relative;z-index:1}
  .head-title small{display:block;font-size:.7rem;font-weight:400;opacity:.85;margin-top:.1rem}
  .card-inner{padding:1.5rem 1.75rem 1.75rem}

  .user-name{font-size:1.25rem;font-weight:700;color:#111827;margin-bottom:1rem;
        letter-spacing:.01em;word-break:break-word}

  .status-badge{display:inline-flex;align-items:center;gap:.4rem;
        padding:.35rem .8rem;border-radius:999px;font-size:.75rem;font-weight:600;
        margin-bottom:1rem}
  .status-badge.ok{background:#dcfce7;color:#16a34a}
  .status-badge.warn{background:#fef3c7;color:#d97706}
  .status-badge.bad{background:#fee2e2;color:#dc2626}
  .status-badge .dot{width:6px;height:6px;border-radius:50%;background:currentColor;
        box-shadow:0 0 0 3px rgba(0,0,0,.05)}

  .hero{background:linear-gradient(135deg,#f5f3ff,#fdf4ff);
        border:1px solid #ede9fe;border-radius:18px;
        padding:1.25rem 1.35rem;margin-bottom:1rem}
  .hero-label{font-size:.75rem;color:#8b5cf6;font-weight:600;
        text-transform:uppercase;letter-spacing:.06em;margin-bottom:.4rem}
  .hero-value{font-size:1.9rem;font-weight:800;color:#111827;line-height:1.1;
        letter-spacing:-.02em}
  .hero-sub{display:flex;justify-content:space-between;flex-wrap:wrap;gap:.4rem;
        font-size:.78rem;color:#6b7280;margin-top:.5rem}
  .hero-remain{color:#4f46e5;font-weight:600}
  .hero-bar{position:relative;height:10px;background:#ede9fe;border-radius:999px;
        overflow:hidden;margin-top:.9rem}
  .hero-bar>i{display:block;height:100%;border-radius:999px;
        background:linear-gradient(90deg,#4f46e5,#7c3aed);transition:width .5s ease}
  .hero-bar.warn>i{background:linear-gradient(90deg,#f59e0b,#f97316)}
  .hero-bar.danger>i{background:linear-gradient(90deg,#ef4444,#dc2626)}
  .hero-percent{text-align:right;font-size:.72rem;color:#9ca3af;margin-top:.4rem;
        font-weight:600}

  .info-grid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:1rem}
  .info-item{display:flex;gap:.7rem;padding:.9rem 1rem;
        background:#fafbfc;border:1px solid #f3f4f6;border-radius:14px;
        min-width:0}
  .info-icon{font-size:1.15rem;line-height:1;flex-shrink:0;margin-top:.15rem}
  .info-body{min-width:0;flex:1}
  .info-label{font-size:.7rem;color:#9ca3af;margin-bottom:.3rem;font-weight:600;
        letter-spacing:.02em}
  .info-value{font-size:.85rem;font-weight:600;color:#111827;
        line-height:1.35;white-space:nowrap;
        overflow:hidden;text-overflow:ellipsis}
  .info-extra{font-size:.72rem;color:#9ca3af;margin-top:.2rem;font-weight:600}
  .info-extra.ok{color:#16a34a} .info-extra.warn{color:#d97706} .info-extra.bad{color:#dc2626}

  .updated{margin-top:1.25rem;padding-top:1rem;border-top:1px solid #f3f4f6;
        font-size:.75rem;color:#9ca3af;display:flex;align-items:center;gap:.5rem;
        flex-wrap:wrap}
  .pulse{width:7px;height:7px;border-radius:50%;background:#22c55e;
        box-shadow:0 0 0 3px rgba(34,197,94,.18);animation:pulse 2s infinite}
  @keyframes pulse{
    0%,100%{box-shadow:0 0 0 3px rgba(34,197,94,.18)}
    50%{box-shadow:0 0 0 6px rgba(34,197,94,.08)}
  }

  .empty{text-align:center;padding:2.5rem 1rem}
  .empty-icon{font-size:3rem;margin-bottom:.9rem;line-height:1}
  .empty p{margin:.4rem 0;color:#6b7280;font-size:.9rem}
  .hint{font-size:.8rem !important;color:#9ca3af !important}
  code{background:#f3f4f6;padding:.15rem .45rem;border-radius:6px;
        font-size:.82rem;color:#4f46e5;font-weight:600}

  .key-form{display:flex;flex-direction:column;gap:.75rem;margin-top:.5rem}
  .key-input-wrap{position:relative}
  .key-input-wrap svg{position:absolute;left:.9rem;top:50%;transform:translateY(-50%);
        width:16px;height:16px;stroke:#9ca3af;pointer-events:none;transition:stroke .2s}
  .key-form input{
        width:100%;padding:.85rem 1rem .85rem 2.6rem;
        border:1.5px solid #e5e7eb;border-radius:12px;
        font-size:.95rem;outline:none;font-family:inherit;
        background:#fafafa;transition:all .2s}
  .key-form input::placeholder{color:#c4c8d0}
  .key-form input:focus{border-color:#4f46e5;background:#fff;
        box-shadow:0 0 0 4px rgba(79,70,229,.10)}
  .key-input-wrap:focus-within svg{stroke:#4f46e5}
  .key-form button{
        padding:.85rem;border:none;border-radius:12px;
        background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;
        font-size:.95rem;font-weight:600;cursor:pointer;font-family:inherit;
        transition:transform .1s,box-shadow .2s;letter-spacing:.02em}
  .key-form button:hover{box-shadow:0 8px 24px rgba(79,70,229,.40)}
  .key-form button:active{transform:scale(.98)}

  body.embed{padding:0;min-height:auto;align-items:stretch;background:#fff}
  body.embed .card{max-width:none;width:100%;border-radius:0;box-shadow:none;min-height:100%}
  body.embed .card-inner{padding:1.5rem 1.75rem}

  @media(max-width:480px){
    body{padding:1rem .75rem}
    .card-inner{padding:1.25rem 1.35rem 1.5rem}
    .head{padding:1rem 1.35rem}
    .head-title small{display:none}
    .info-grid{grid-template-columns:1fr}
    .info-item{padding:.85rem .95rem}
    .info-value{font-size:.82rem;white-space:normal;overflow:visible;text-overflow:clip}
    .hero-value{font-size:1.65rem}
    .hero{padding:1.1rem 1.15rem}
    .updated{font-size:.72rem}
    body.embed .card-inner{padding:1.25rem 1.35rem}
  }
</style></head><body class="${bodyClass}">
<div class="card">
  <div class="head">
    <div class="logo"><img src="${LOGO_URL}" alt="logo"></div>
    <div class="head-title">流量查询<small>数据实时同步</small></div>
  </div>
  <div class="card-inner">
    <div class="user-name">${escapeHtml(title)}</div>
    ${body}
  </div>
</div>
</body></html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}
