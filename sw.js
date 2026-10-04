// Decrypts the pictures and voice clips of Their Lives in the browser. Every file under media/ is stored encrypted
// (12 byte IV, then AES-GCM ciphertext); the key comes from the page after the password is typed and is kept in IndexedDB.
const TYPES = {html: 'text/html; charset=utf-8', vtt: 'text/vtt; charset=utf-8', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', mp4: 'audio/mp4', m4a: 'audio/mp4'};
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
// a video is stored in parts of 1 MB with an index (see ghbuild.py), so a range of it can be served after decrypting a few parts
const vcache = new Map(); // url#part -> decrypted part
async function vindex(url) { return JSON.parse(new TextDecoder().decode(await plain(url + '.json'))); }
async function vpart(url, k) { const key = url + '#' + k; if (vcache.has(key)) return vcache.get(key);
  const out = await plain(url + '.p' + String(k).padStart(3, '0')); vcache.set(key, out); while (vcache.size > 24) vcache.delete(vcache.keys().next().value); return out; }
async function video(e, url) {
  const idx = await vindex(url); const total = idx.total, P = idx.part; const range = e.request.headers.get('range');
  let a = 0, b = total - 1, partial = false;
  if (range) { const m = /bytes=(\d*)-(\d*)/.exec(range); partial = true;
    if (m && m[1]) a = +m[1]; if (m && m[2]) b = +m[2]; if (m && !m[1] && m[2]) { a = Math.max(0, total - +m[2]); b = total - 1; }
    if (a >= total) return new Response(null, {status: 416, headers: {'Content-Range': 'bytes */' + total}});
    b = Math.min(b, total - 1, a + 4 * P - 1); }
  const k0 = Math.floor(a / P), k1 = Math.floor(b / P); const parts = [];
  for (let k = k0; k <= k1; k++) parts.push(new Uint8Array(await vpart(url, k)));
  const out = new Uint8Array(b - a + 1); let pos = 0;
  for (let k = k0; k <= k1; k++) { const p = parts[k - k0]; const from = k === k0 ? a - k0 * P : 0, to = k === k1 ? b - k1 * P + 1 : p.length; out.set(p.subarray(from, to), pos); pos += to - from; }
  const headers = {'Content-Type': 'video/mp4', 'Accept-Ranges': 'bytes', 'Content-Length': String(out.length)};
  if (partial) { headers['Content-Range'] = `bytes ${a}-${b}/${total}`; return new Response(out, {status: 206, headers}); }
  return new Response(out, {status: 200, headers});
}
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || !u.pathname.includes('/media/') || e.request.method !== 'GET') return;
  e.respondWith((async () => {
    try {
      const url = u.origin + u.pathname;
      if (u.pathname.includes('/media/video/') && u.pathname.endsWith('.mp4')) return await video(e, url);
      const body = await plain(url);
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
