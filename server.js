require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const OTP_TTL_MS = 5 * 60 * 1000;      // OTP valid for 5 minutes
const RESEND_COOLDOWN_MS = 30 * 1000;  // 30s between sends
const MAX_ATTEMPTS = 3;                // wrong guesses before OTP is burned
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 min session

const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const transporter = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

if (!smtpConfigured) {
  console.warn('\n[!] SMTP is not configured (.env missing). OTPs will be printed here in the console instead of emailed.\n');
}

const otpStore = new Map();     // identifier -> { hash, email, expires, attempts, lastSent }
const sessionStore = new Map(); // token -> { email, expires }

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_RE = /^(\+?91)?[6-9]\d{9}$/;

function maskEmail(e) {
  const [u, d] = e.split('@');
  return u.slice(0, 2) + '*'.repeat(Math.max(u.length - 2, 2)) + '@' + d;
}

function resolveIdentifier(raw) {
  const id = String(raw || '').trim().toLowerCase().replace(/[\s-]/g, '');
  if (EMAIL_RE.test(id)) return { key: id, email: id };
  if (PHONE_RE.test(id)) {
    const email = process.env.PHONE_LOGIN_EMAIL;
    if (!email) return { error: 'Phone login is not set up. Add PHONE_LOGIN_EMAIL to .env.' };
    return { key: id.slice(-10), email };
  }
  return { error: 'Enter a valid email address or 10-digit mobile number.' };
}

function otpEmailHtml(code) {
  return `
  <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;border:1px solid #e3e6e4;border-radius:8px;overflow:hidden">
    <div style="background:#0f3d3a;color:#fff;padding:18px 24px;font-size:18px;font-weight:bold">Kestrel Bank</div>
    <div style="padding:24px;color:#1b2523">
      <p style="margin:0 0 12px">Use this one-time password to sign in to Kestrel NetBanking:</p>
      <p style="font-size:34px;letter-spacing:8px;font-weight:bold;margin:16px 0;color:#0f3d3a">${code}</p>
      <p style="margin:0 0 8px;font-size:14px">It expires in 5 minutes. Never share this code with anyone, including Kestrel Bank staff.</p>
      <p style="margin:16px 0 0;font-size:12px;color:#6b7774">This is a fictional bank used as a film prop.</p>
    </div>
  </div>`;
}

// ---------- API ----------
app.post('/api/request-otp', async (req, res) => {
  const r = resolveIdentifier(req.body.identifier);
  if (r.error) return res.status(400).json({ ok: false, message: r.error });

  const existing = otpStore.get(r.key);
  if (existing && Date.now() - existing.lastSent < RESEND_COOLDOWN_MS) {
    const wait = Math.ceil((RESEND_COOLDOWN_MS - (Date.now() - existing.lastSent)) / 1000);
    return res.status(429).json({ ok: false, message: `Please wait ${wait}s before requesting another OTP.` });
  }

  const code = crypto.randomInt(100000, 1000000).toString();
  try {
    if (transporter) {
      await transporter.sendMail({
        from: process.env.MAIL_FROM || process.env.SMTP_USER,
        to: r.email,
        subject: `${code} is your Kestrel Bank OTP`,
        text: `Your Kestrel Bank one-time password is ${code}. It expires in 5 minutes. Do not share it with anyone.`,
        html: otpEmailHtml(code),
      });
    } else {
      console.log(`[DEV] OTP for ${r.key} -> ${r.email}: ${code}`);
    }
  } catch (err) {
    console.error('SMTP error:', err.message);
    return res.status(502).json({ ok: false, message: 'Could not send the OTP email. Check your SMTP settings.' });
  }

  otpStore.set(r.key, { hash: sha(code), email: r.email, expires: Date.now() + OTP_TTL_MS, attempts: 0, lastSent: Date.now() });
  res.json({ ok: true, sentTo: maskEmail(r.email), cooldown: RESEND_COOLDOWN_MS / 1000 });
});

app.post('/api/verify-otp', (req, res) => {
  const r = resolveIdentifier(req.body.identifier);
  if (r.error) return res.status(400).json({ ok: false, message: r.error });

  const rec = otpStore.get(r.key);
  if (!rec) return res.status(400).json({ ok: false, message: 'Request an OTP first.' });
  if (Date.now() > rec.expires) {
    otpStore.delete(r.key);
    return res.status(400).json({ ok: false, message: 'This OTP has expired. Request a new one.' });
  }

  const submitted = String(req.body.otp || '').trim();
  const ok = /^\d{6}$/.test(submitted) && crypto.timingSafeEqual(sha(submitted), rec.hash);
  if (!ok) {
    rec.attempts += 1;
    if (rec.attempts >= MAX_ATTEMPTS) {
      otpStore.delete(r.key);
      return res.status(401).json({ ok: false, message: 'Too many incorrect attempts. Request a new OTP.' });
    }
    return res.status(401).json({ ok: false, message: `Incorrect OTP. ${MAX_ATTEMPTS - rec.attempts} attempt(s) left.` });
  }

  otpStore.delete(r.key);
  const token = crypto.randomBytes(32).toString('hex');
  sessionStore.set(token, { email: rec.email, expires: Date.now() + SESSION_TTL_MS });
  res.setHeader('Set-Cookie', `kb_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`);
  res.json({ ok: true, redirect: '/dashboard' });
});

// ---------- Pages ----------
function getSession(req) {
  const m = /(?:^|;\s*)kb_session=([a-f0-9]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const s = sessionStore.get(m[1]);
  if (!s || Date.now() > s.expires) { sessionStore.delete(m[1]); return null; }
  return { token: m[1], ...s };
}

app.get('/dashboard', (req, res) => {
  const s = getSession(req);
  if (!s) return res.redirect('/');
  const html = fs.readFileSync(path.join(__dirname, 'views', 'dashboard.html'), 'utf8')
    .replace(/{{EMAIL}}/g, s.email);
  res.type('html').send(html);
});

app.get('/logout', (req, res) => {
  const s = getSession(req);
  if (s) sessionStore.delete(s.token);
  res.setHeader('Set-Cookie', 'kb_session=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/');
});

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`Kestrel Bank prop running at http://localhost:${PORT}`));
