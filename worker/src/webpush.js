// Web Push (RFC 8291 aes128gcm) + VAPID (RFC 8292) ด้วย WebCrypto ล้วน
// ใช้ได้ทั้งใน Cloudflare Worker และใน node ตอนเทสต์ — ห้ามพึ่ง API ของ node
// พลาดตรงนี้แล้วจะเงียบสนิทแบบไม่มี error เลยต้องมีเทสต์ถอดรหัสกลับคุมไว้

const enc = new TextEncoder();

export function b64uToBytes(s) {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(pad + "===".slice((pad.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64u(b) {
  let s = "";
  const a = new Uint8Array(b);
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

async function hmac(keyBytes, data) {
  const k = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

// HKDF ที่ยาวไม่เกิน 32 ไบต์ = expand รอบเดียวพอ
async function hkdf(salt, ikm, info, len) {
  const prk = await hmac(salt, ikm);
  const okm = await hmac(prk, concat(info, new Uint8Array([1])));
  return okm.slice(0, len);
}

function importUaPublic(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

// คืนค่าตามรูปแบบ body ของ aes128gcm: salt | rs | idlen | as_public | ciphertext
export async function encryptPayload(p256dhB64u, authB64u, plaintext) {
  const uaPublicRaw = b64uToBytes(p256dhB64u);
  const authSecret = b64uToBytes(authB64u);

  const asKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", asKeys.publicKey));

  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: await importUaPublic(uaPublicRaw) }, asKeys.privateKey, 256));

  const keyInfo = concat(enc.encode("WebPush: info\0"), uaPublicRaw, asPublicRaw);
  const ikm = await hkdf(authSecret, shared, keyInfo, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);

  const key = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const record = concat(enc.encode(plaintext), new Uint8Array([2]));   // 0x02 = เรกคอร์ดสุดท้าย
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, record));

  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096);
  return concat(salt, rs, new Uint8Array([asPublicRaw.length]), asPublicRaw, ct);
}

async function importVapidKey(jwk) {
  return crypto.subtle.importKey("jwk",
    { kty: "EC", crv: "P-256", d: jwk.d, x: jwk.x, y: jwk.y, ext: true },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

export async function vapidHeaders(endpoint, privateJwk, publicKeyB64u, subject) {
  const aud = new URL(endpoint).origin;
  const head = bytesToB64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = bytesToB64u(enc.encode(JSON.stringify({
    aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject,
  })));
  const signing = enc.encode(head + "." + body);
  const sig = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, await importVapidKey(privateJwk), signing));
  return "vapid t=" + head + "." + body + "." + bytesToB64u(sig) + ", k=" + publicKeyB64u;
}

// ส่งจริง — คืน status ของ push service ไว้ให้ผู้เรียกตัดสินใจ (410/404 = subscription ตายแล้ว)
export async function sendPush(sub, text, env) {
  const privateJwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const auth = await vapidHeaders(sub.endpoint, privateJwk, env.VAPID_PUBLIC_KEY, env.VAPID_SUBJECT);
  const body = await encryptPayload(sub.keys.p256dh, sub.keys.auth, text);
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      Authorization: auth,
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: "120",                       // หมดเวลาพักแล้วเกินสองนาที ส่งไปก็ไม่มีประโยชน์
      Urgency: "high",
    },
    body,
  });
  return { ok: res.ok, status: res.status, text: res.ok ? "" : await res.text() };
}
