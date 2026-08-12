// เซิร์ฟเวอร์ตั้งเวลายิง push — Durable Object ตัวหนึ่งต่อหนึ่งเครื่อง
// ใช้ alarm() ของ DO เพราะ cron ของ Workers ละเอียดสุดแค่ 1 นาที ซึ่งหยาบเกินไปสำหรับพัก 90 วิ
import { sendPush } from "./webpush.js";

const MAX_SEC = 3600;          // พักเกินชั่วโมงถือว่าผิดปกติ ไม่รับ
const MAX_TRIES = 3;
// iOS ไม่สนใจ requireInteraction แบนเนอร์หุบเองเสมอ เลยต้องเตือนซ้ำเป็นระยะแทน
// หยุดเมื่อได้ /api/cancel (แตะแจ้งเตือน หรือกลับเข้าแอป) หรือครบจำนวนรอบ
const MAX_RINGS = 7;
const RING_GAP_MS = 8000;      // 7 รอบ ห่างละ 8 วิ = ปลุกอยู่ราว 48 วินาที

function cors(env, extra) {
  return Object.assign({
    "Access-Control-Allow-Origin": env.ALLOW_ORIGIN || "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  }, extra || {});
}
function json(env, obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: cors(env, { "Content-Type": "application/json" }),
  });
}
function validSub(s) {
  return !!(s && typeof s.endpoint === "string" && /^https:\/\//.test(s.endpoint) &&
            s.keys && typeof s.keys.p256dh === "string" && typeof s.keys.auth === "string");
}

export class RestAlarm {
  constructor(state, env) { this.state = state; this.env = env; }

  async fetch(request) {
    const act = new URL(request.url).pathname.split("/").pop();
    // sendBeacon ส่งมาเป็น text/plain เพื่อเลี่ยง preflight — อ่านเป็นข้อความแล้วค่อย parse
    let data = {};
    try { data = JSON.parse(await request.text()); } catch (e) {}

    if (act === "cancel") {
      await this.state.storage.deleteAlarm();
      return json(this.env, { ok: true });
    }
    if (!validSub(data.sub)) return json(this.env, { error: "subscription ไม่ถูกต้อง" }, 400);

    if (act === "test") {
      const r = await sendPush(data.sub, JSON.stringify({
        title: "ทดสอบเสียงเตือน", body: "ถ้าได้ยินเสียงนี้ตอนอยู่แอปอื่น แปลว่าใช้ได้แล้ว",
      }), this.env);
      console.log("TEST ยิง push: ok=" + r.ok + " status=" + r.status +
                  (r.text ? " ตอบกลับ=" + String(r.text).slice(0, 300) : ""));
      return json(this.env, r, r.ok ? 200 : 502);
    }
    if (act === "schedule") {
      const sec = Number(data.inSec);
      if (!(sec > 0 && sec <= MAX_SEC)) return json(this.env, { error: "เวลาไม่ถูกต้อง" }, 400);
      // ยึดนาฬิกาเซิร์ฟเวอร์ ไม่ใช่เวลาที่เครื่องส่งมา เผื่อนาฬิกาสองฝั่งไม่ตรงกัน
      await this.state.storage.put({ sub: data.sub, tries: 0, rings: 0 });
      await this.state.storage.setAlarm(Date.now() + sec * 1000);
      console.log("SCHEDULE จองไว้อีก " + sec + " วินาที");
      return json(this.env, { ok: true, at: Date.now() + sec * 1000 });
    }
    return json(this.env, { error: "not found" }, 404);
  }

  async alarm() {
    const sub = await this.state.storage.get("sub");
    if (!validSub(sub)) return;
    const tries = (await this.state.storage.get("tries")) || 0;
    const rings = (await this.state.storage.get("rings")) || 0;

    const r = await sendPush(sub, JSON.stringify({
      title: "พักครบแล้ว", body: "แตะเพื่อหยุดเตือน แล้วกลับไปเซตต่อไป",
    }), this.env);

    // ตัว alarm ไม่ใช่ HTTP request เลยไม่โผล่ในล็อกเอง ต้อง log เองถึงจะไล่ปัญหาได้
    console.log("ALARM ยิง push: ok=" + r.ok + " status=" + r.status +
                " ปลุกรอบที่=" + (rings + 1) + "/" + MAX_RINGS +
                (r.text ? " ตอบกลับ=" + String(r.text).slice(0, 300) : ""));

    if (!r.ok) {
      if (r.status === 404 || r.status === 410) {  // subscription ตายแล้ว ลองอีกก็เท่านั้น
        await this.state.storage.delete("sub");
        return;
      }
      if (tries + 1 >= MAX_TRIES) return;          // มีเพดาน ไม่งั้น alarm ปลุกตัวเองวนไม่จบ
      await this.state.storage.put("tries", tries + 1);
      await this.state.storage.setAlarm(Date.now() + 3000);
      return;
    }

    // ส่งผ่านแล้ว — เตือนซ้ำจนกว่าจะแตะ (จะมี /api/cancel เข้ามาลบนัดทิ้ง) หรือครบรอบ
    await this.state.storage.put({ tries: 0, rings: rings + 1 });
    if (rings + 1 < MAX_RINGS) await this.state.storage.setAlarm(Date.now() + RING_GAP_MS);
  }
}

async function idFor(env, sub) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sub.endpoint));
  const hex = Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return env.REST_ALARM.idFromName(hex);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(env) });
    if (url.pathname === "/health") return json(env, { ok: true });
    if (request.method !== "POST") return json(env, { error: "method not allowed" }, 405);

    const act = url.pathname.replace(/^\/api\//, "");
    if (!/^(schedule|cancel|test)$/.test(act)) return json(env, { error: "not found" }, 404);

    const raw = await request.text();
    let data = {};
    try { data = JSON.parse(raw); } catch (e) { return json(env, { error: "json ไม่ถูกต้อง" }, 400); }
    if (!validSub(data.sub)) return json(env, { error: "subscription ไม่ถูกต้อง" }, 400);

    const stub = env.REST_ALARM.get(await idFor(env, data.sub));
    return stub.fetch(new Request("https://do/" + act, { method: "POST", body: raw }));
  },
};
