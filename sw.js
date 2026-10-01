// Decrypts the pictures and voice clips of Their Lives in the browser. Every file under media/ is stored encrypted
// (12 byte IV, then AES-GCM ciphertext); the key comes from the page after the password is typed and is kept in IndexedDB.
const TYPES = {jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', mp4: 'audio/mp4', m4a: 'audio/mp4'};
let KEY = null;
const cache = new Map(); // url -> decrypted ArrayBuffer, the few most recent
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
function idb() { return new Promise((ok, no) => { const r = indexedDB.open('their-lives', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error); }); }
async function saveKey(k) { const db = await idb(); await new Promise((ok, no) => { const t = db.transaction('k', 'readwrite');
  t.objectStore('k').put(k, 'key'); t.oncomplete = ok; t.onerror = () => no(t.error); }); }
async function loadKey() { if (KEY) return KEY; try { const db = await idb();
  KEY = await new Promise(ok => { const q = db.transaction('k').objectStore('k').get('key'); q.onsuccess = () => ok(q.result || null); q.onerror = () => ok(null); });
} catch (e) {} return KEY; }
self.addEventListener('message', e => {
  if (!e.data || e.data.type !== 'key') return;
  e.waitUntil((async () => {
    KEY = await crypto.subtle.importKey('raw', e.data.raw, 'AES-GCM', false, ['decrypt']);
    try { await saveKey(KEY); } catch (err) {}
    if (e.ports && e.ports[0]) e.ports[0].postMessage('ok');
  })());
});
async function plain(url) {
  if (cache.has(url)) { const b = cache.get(url); cache.delete(url); cache.set(url, b); return b; }
  const key = await loadKey(); if (!key) throw new Error('locked');
  const r = await fetch(url, {cache: 'force-cache'}); if (!r.ok) throw new Error('fetch ' + r.status);
  const buf = new Uint8Array(await r.arrayBuffer());
  const out = await crypto.subtle.decrypt({name: 'AES-GCM', iv: buf.slice(0, 12)}, key, buf.slice(12));
  cache.set(url, out); while (cache.size > 12) cache.delete(cache.keys().next().value);
  return out;
}
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || !u.pathname.includes('/media/') || e.request.method !== 'GET') return;
  e.respondWith((async () => {
    try {
      const url = u.origin + u.pathname; const body = await plain(url);
      const type = TYPES[(u.pathname.split('.').pop() || '').toLowerCase()] || 'application/octet-stream';
      const total = body.byteLength; const range = e.request.headers.get('range');
      if (range) {
        const m = /bytes=(\d*)-(\d*)/.exec(range); let a = m && m[1] ? +m[1] : 0, b = m && m[2] ? +m[2] : total - 1;
        if (m && !m[1] && m[2]) { a = Math.max(0, total - +m[2]); b = total - 1; }
        b = Math.min(b, total - 1);
        if (a >= total) return new Response(null, {status: 416, headers: {'Content-Range': 'bytes */' + total}});
        return new Response(body.slice(a, b + 1), {status: 206, headers: {'Content-Type': type, 'Content-Range': `bytes ${a}-${b}/${total}`, 'Content-Length': String(b - a + 1), 'Accept-Ranges': 'bytes'}});
      }
      return new Response(body, {status: 200, headers: {'Content-Type': type, 'Content-Length': String(total), 'Accept-Ranges': 'bytes'}});
    } catch (err) { return new Response('', {status: 404}); }
  })());
});
