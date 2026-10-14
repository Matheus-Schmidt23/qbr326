// Acesso protegido por senha ao deck do QBR Q3 2026.
// A senha fica na variável de ambiente QBR_PASSWORD (Vercel), nunca no código.
// O deck só é entregue pelo servidor depois da senha correta.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const COOKIE = 'qbr_auth';
const MAX_AGE = 60 * 60 * 24 * 7; // 7 dias

let gzCache = null;
// O deck fica criptografado no repositório (AES-256, formato OpenSSL com PBKDF2).
// Só é aberto no servidor, com a senha da variável QBR_PASSWORD.
function deckGz(password) {
  if (gzCache) return gzCache;
  const raw = fs.readFileSync(path.join(__dirname, "..", "private", "deck.enc"));
  if (raw.subarray(0, 8).toString() !== "Salted__") throw new Error("formato inesperado");
  const salt = raw.subarray(8, 16);
  const kiv = crypto.pbkdf2Sync(password, salt, 600000, 48, "sha256");
  const d = crypto.createDecipheriv("aes-256-cbc", kiv.subarray(0, 32), kiv.subarray(32, 48));
  gzCache = Buffer.concat([d.update(raw.subarray(16)), d.final()]);
  return gzCache;
}

function token(password) {
  return crypto.createHmac('sha256', password).update('pm3-qbr-q3-2026:v1').digest('hex');
}

function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 4096) req.destroy(); });
    req.on('end', () => resolve(data));
    req.on('error', () => resolve(''));
  });
}

function loginPage(error) {
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>QBR Q3 2026 · Acesso</title>
<style>
  :root{ --deep:#452E78; --royal:#6645B1; --yellow:#FFB12A; --fog:#B9B5C1; }
  *{ box-sizing:border-box; margin:0; }
  body{ min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px;
    font-family:"Inter Tight","Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    background:radial-gradient(1200px 700px at 15% 10%, #6645B1 0%, #452E78 45%, #1d1233 100%); color:#fff; }
  .card{ width:100%; max-width:420px; background:rgba(255,255,255,.07); border:1px solid rgba(255,255,255,.18);
    border-radius:28px; padding:40px 34px 34px; backdrop-filter:blur(8px); position:relative; overflow:hidden; }
  .card::before{ content:""; position:absolute; left:0; top:34px; bottom:34px; width:6px; border-radius:0 6px 6px 0; background:var(--yellow); }
  .kick{ font-size:12px; letter-spacing:.18em; text-transform:uppercase; font-weight:700; color:var(--fog); }
  h1{ font-size:34px; line-height:1.08; letter-spacing:-.02em; margin:12px 0 8px; font-weight:800; }
  p{ font-size:15px; line-height:1.5; color:#E6E1F2; margin-bottom:24px; }
  label{ display:block; font-size:12px; letter-spacing:.12em; text-transform:uppercase; font-weight:700; color:var(--fog); margin-bottom:8px; }
  input{ width:100%; height:52px; border-radius:14px; border:1.5px solid rgba(255,255,255,.28); background:rgba(0,0,0,.25);
    color:#fff; font-size:17px; padding:0 16px; outline:none; font-family:inherit; }
  input:focus{ border-color:var(--yellow); }
  button{ width:100%; height:52px; margin-top:16px; border:0; border-radius:14px; background:var(--yellow); color:#000;
    font-size:16px; font-weight:800; letter-spacing:.02em; cursor:pointer; font-family:inherit; }
  button:hover{ filter:brightness(1.06); }
  .err{ margin-top:14px; font-size:14px; color:#FFD0D0; background:rgba(255,80,80,.16); border:1px solid rgba(255,120,120,.4);
    border-radius:12px; padding:10px 14px; }
  .foot{ margin-top:22px; font-size:12px; color:var(--fog); }
</style>
</head>
<body>
  <form class="card" method="post" action="/" autocomplete="off">
    <div class="kick">Grupo Alun · PM3</div>
    <h1>QBR Q3 2026</h1>
    <p>Apresentação de uso restrito. Digite a senha para continuar.</p>
    <label for="p">Senha</label>
    <input id="p" name="password" type="password" autofocus required autocomplete="current-password">
    ${error ? '<div class="err">Senha incorreta. Tente novamente.</div>' : ''}
    <button type="submit">Entrar</button>
    <div class="foot">Julho a setembro de 2026</div>
  </form>
</body>
</html>`;
}

function send(res, status, body, extra) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  for (const [k, v] of Object.entries(extra || {})) res.setHeader(k, v);
  res.end(body);
}

module.exports = async (req, res) => {
  const password = process.env.QBR_PASSWORD;
  if (!password) return send(res, 500, 'Configuração ausente: defina QBR_PASSWORD.');

  const expected = token(password);
  const logged = safeEqual(readCookie(req, COOKIE), expected);

  if (req.method === 'POST') {
    const body = await readBody(req);
    const given = new URLSearchParams(body).get('password') || '';
    if (safeEqual(given, password)) {
      res.statusCode = 303;
      res.setHeader('Set-Cookie', `${COOKIE}=${expected}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`);
      res.setHeader('Location', '/');
      res.setHeader('Cache-Control', 'private, no-store');
      return res.end();
    }
    await new Promise((r) => setTimeout(r, 900)); // freia tentativas em sequência
    return send(res, 401, loginPage(true));
  }

  if (req.url && /^\/logout\/?$/.test(req.url.split('?')[0])) {
    res.statusCode = 303;
    res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
    res.setHeader('Location', '/');
    return res.end();
  }

  if (!logged) return send(res, 200, loginPage(false));
  return sendDeck(req, res, password);
};

// O deck tem mais de 4,5 MB: vai compactado (gzip) e em partes (streaming),
// para não esbarrar no limite de tamanho de resposta das funções.
function sendDeck(req, res, password) {
  const wantsGzip = /gzip/.test(req.headers["accept-encoding"] || "");
  let body;
  try { body = deckGz(password); } catch (e) { return send(res, 500, "Erro ao abrir o conteúdo."); }
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "private, no-store");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Vary", "Accept-Encoding, Cookie");
  if (wantsGzip) res.setHeader("Content-Encoding", "gzip");
  else body = require("zlib").gunzipSync(body);
  const CHUNK = 256 * 1024;
  for (let i = 0; i < body.length; i += CHUNK) res.write(body.subarray(i, i + CHUNK));
  res.end();
}
