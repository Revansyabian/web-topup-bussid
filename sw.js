const CACHE_NAME = 'bussid-topup-v2';
const urlsToCache = [
    '/',
    '/index.html',
    '/style.css',
    '/main.js',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
];

self.addEventListener('install', function(e) {
    self.skipWaiting();
    e.waitUntil(
        caches.open(CACHE_NAME).then(function(cache) {
            return Promise.allSettled(
                urlsToCache.map(function(url) {
                    return cache.add(url).catch(function() {});
                })
            );
        })
    );
});

self.addEventListener('activate', function(e) {
    e.waitUntil(
        caches.keys().then(function(names) {
            return Promise.all(
                names.filter(function(name) {
                    return name !== CACHE_NAME;
                }).map(function(name) {
                    return caches.delete(name);
                })
            );
        })
    );
    e.waitUntil(clients.claim());
});

self.addEventListener('fetch', function(e) {
    if (e.request.method !== 'GET') return;
    
    e.respondWith(
        caches.match(e.request).then(function(cached) {
            return cached || fetch(e.request).then(function(response) {
                if (response.status === 200) {
                    var clone = response.clone();
                    caches.open(CACHE_NAME).then(function(cache) {
                        cache.put(e.request, clone);
                    });
                }
                return response;
            });
        }).catch(function() {
            return caches.match('/index.html');
        })
    );
});