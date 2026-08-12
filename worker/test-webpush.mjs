// เทสต์ว่าที่เข้ารหัสไปถอดกลับได้จริง — จำลองฝั่งเบราว์เซอร์เป็นคนถอด
// รันด้วย: node worker/test-webpush.mjs
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const { encryptPayload, vapidHeaders, bytesToB64u, b64uToBytes } = await import("./src/webpush.js");

const enc = new TextEncoder(), dec = new TextDecoder();
function concat(...ps) {
  const out = new Uint8Array(ps.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of ps) { out.set(p, o); o += p.length; }
  return out;
}
async function hmac(k, d) {
  const key = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, d));
}
async function hkdf(salt, ikm, info, len) {
  const prk = await hmac(salt, ikm);
  return (await hmac(prk, concat(info, new Uint8Array([1])))).slice(0, len);
}

let pass = 0, fail = 0;
const ok = (name, cond, extra) => { if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (extra ? " — " + extra : "")); } };

// ---- ฝั่งเบราว์เซอร์: สร้างคู่กุญแจ subscription ปลอมขึ้นมา ----
const ua = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
const uaPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ua.publicKey));
const authSecret = crypto.getRandomValues(new Uint8Array(16));

const plaintext = JSON.stringify({ title: "พักครบแล้ว", body: "กลับไปเซตต่อไปได้เลย" });
const body = await encryptPayload(bytesToB64u(uaPublicRaw), bytesToB64u(authSecret), plaintext);

// ---- ถอดรหัสกลับตาม RFC 8291 ----
const salt = body.slice(0, 16);
const rs = new DataView(body.buffer, body.byteOffset + 16, 4).getUint32(0);
const idlen = body[20];
const asPublicRaw = body.slice(21, 21 + idlen);
const ct = body.slice(21 + idlen);

ok("rs = 4096", rs === 4096, "ได้ " + rs);
ok("ความยาวกุญแจฝั่งเซิร์ฟเวอร์ 65 ไบต์", idlen === 65, "ได้ " + idlen);

const asPublic = await crypto.subtle.importKey("raw", asPublicRaw, { name: "ECDH", namedCurve: "P-256" }, true, []);
const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: asPublic }, ua.privateKey, 256));
const ikm = await hkdf(authSecret, shared, concat(enc.encode("WebPush: info\0"), uaPublicRaw, asPublicRaw), 32);
const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
const key = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["decrypt"]);

let got = null, err = null;
try {
  const rec = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct));
  ok("ไบต์ปิดท้ายเรกคอร์ดเป็น 0x02", rec[rec.length - 1] === 2, "ได้ 0x" + rec[rec.length - 1].toString(16));
  got = dec.decode(rec.slice(0, -1));
} catch (e) { err = e.message; }

ok("ถอดรหัสกลับได้ตรงกับต้นฉบับ", got === plaintext, err || JSON.stringify(got));

// ---- VAPID JWT ----
const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
const hdr = await vapidHeaders("https://web.push.apple.com/abc123", jwk, bytesToB64u(pubRaw), "mailto:a@b.c");

const m = /^vapid t=([^,]+), k=(.+)$/.exec(hdr);
ok("รูปแบบ header ถูกต้อง", !!m);
if (m) {
  const [h, p, s] = m[1].split(".");
  const claims = JSON.parse(dec.decode(b64uToBytes(p)));
  ok("aud = origin ของ endpoint", claims.aud === "https://web.push.apple.com", claims.aud);
  ok("exp ไม่เกิน 24 ชม.", claims.exp - Math.floor(Date.now() / 1000) <= 86400);
  ok("ลายเซ็น 64 ไบต์ (raw r||s ไม่ใช่ DER)", b64uToBytes(s).length === 64, b64uToBytes(s).length + " ไบต์");
  const verified = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, kp.publicKey,
    b64uToBytes(s), enc.encode(h + "." + p));
  ok("ตรวจลายเซ็นผ่าน", verified);
  ok("k = public key ของเรา", m[2] === bytesToB64u(pubRaw));
}

console.log("\n" + pass + " ผ่าน, " + fail + " ตก");
process.exit(fail ? 1 : 0);
