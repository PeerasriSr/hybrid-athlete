// Service worker เอาไว้รับ push อย่างเดียว
// ห้ามใส่ fetch handler หรือ cache เด็ดขาด — จะทำให้เครื่องค้างเวอร์ชันเก่า
// แล้วเช็คไม่ได้ว่าโหลดไฟล์ใหม่แล้วจริงไหม
self.addEventListener("install", function (e) { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });

self.addEventListener("push", function (e) {
  var d = { title: "พักครบแล้ว", body: "กลับไปเซตต่อไปได้เลย" };
  try { if (e.data) d = Object.assign(d, e.data.json()); } catch (err) {}
  e.waitUntil(self.registration.showNotification(d.title, {
    body: d.body,
    tag: "hybrid-rest",
    renotify: true,
    requireInteraction: true,          // ค้างไว้จนกด ไม่หายไปเองตอนไม่ได้มอง
    data: { at: Date.now() },
  }));
});

self.addEventListener("notificationclick", function (e) {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (list) {
    for (var i = 0; i < list.length; i++) {
      if ("focus" in list[i]) return list[i].focus();
    }
    if (self.clients.openWindow) return self.clients.openWindow("./");
  }));
});
