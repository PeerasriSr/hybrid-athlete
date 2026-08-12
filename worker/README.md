# hybrid-rest-push

เซิร์ฟเวอร์ยิงแจ้งเตือนตอนหมดเวลาพัก ให้เตือนได้แม้สลับไปแอปอื่น

- ปลายทาง: https://hybrid-rest-push.peerasrisrimaroeng.workers.dev
- Durable Object `RestAlarm` ตัวหนึ่งต่อหนึ่งเครื่อง (id = SHA-256 ของ endpoint)
  ใช้ `alarm()` เพราะ cron ของ Workers ละเอียดสุดแค่ 1 นาที

## แก้แล้ว deploy ใหม่

    cd worker
    npm run deploy        # = npx wrangler@3 deploy

ต้องตรึงไว้ที่ wrangler 3 เพราะเครื่องนี้เป็น Node 18 ส่วน wrangler 4 ต้อง Node 22 ขึ้นไป

## เทสต์

    node test-webpush.mjs   # ตรวจการเข้ารหัส aes128gcm + VAPID โดยถอดรหัสกลับ

## กุญแจ

- public อยู่ใน `wrangler.toml` และใน index.html (เปิดเผยได้)
- private อยู่ใน `vapid-private.json` (ไม่เข้า git) และอัปโหลดเป็น secret แล้วด้วย

      cat vapid-private.json | npx wrangler@3 secret put VAPID_PRIVATE_JWK

ถ้าเปลี่ยนคู่กุญแจ ต้องเปลี่ยนทั้งสามที่ แล้วให้เครื่องกดเปิดเตือนใหม่ (subscription เดิมใช้ไม่ได้)
