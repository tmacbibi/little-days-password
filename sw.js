const CACHE='little-days-password-v1-2-1';
const ASSETS=['./','./index.html','./styles.css?v=1.2.1','./app.js?v=1.2.1','./manifest.json?v=1.2.1','./icons/icon-192.png','./icons/icon-512.png'];

self.addEventListener('install',e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting()));
});

self.addEventListener('activate',e=>{
  e.waitUntil(
    caches.keys()
      .then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))
      .then(()=>self.clients.claim())
  );
});

self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET') return;
  const url = new URL(e.request.url);
  if(url.origin !== self.location.origin) return;

  // Network-first so newly deployed versions appear quickly; cache is the offline fallback.
  e.respondWith(
    fetch(e.request)
      .then(resp=>{
        const copy=resp.clone();
        caches.open(CACHE).then(c=>c.put(e.request,copy));
        return resp;
      })
      .catch(async()=>{
        const cached=await caches.match(e.request);
        if(cached) return cached;
        if(e.request.mode==='navigate') return caches.match('./index.html');
        throw new Error('offline');
      })
  );
});
