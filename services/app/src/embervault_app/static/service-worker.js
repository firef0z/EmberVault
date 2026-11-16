/**
 * EmberVault Service Worker (PWA Shell Caching)
 * Rules: Caches only static assets and /offline fallback. Never caches /api or mutating requests.
 */

const CACHE_NAME = 'embervault-shell-v8';
const STATIC_ASSETS = [
  '/offline',
  '/static/css/app.css',
  '/static/js/app.js',
  '/static/js/proxies.js',
  '/static/js/sw-register.js',
  '/static/manifest.webmanifest',
  '/static/img/logo.svg',
  '/static/img/icon-192.svg',
  '/static/img/icon-512.svg'
];

// Install: precache the core shell
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    }).then(() => self.skipWaiting())
  );
});

// Activate: clean up old caches immediately
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch: network-first for navigation and static assets with offline/cache fallback
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);

  // Never cache POST, PUT, DELETE or API requests
  if (request.method !== 'GET' || url.pathname.startsWith('/api/') || url.pathname.startsWith('/metrics')) {
    return;
  }

  // Handle page navigation: network-first, offline fallback
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => {
        return caches.match('/offline');
      })
    );
    return;
  }

  // Handle static assets: network-first to ensure css/js fixes apply immediately, fallback to cache
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      fetch(request)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const copy = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
            return networkResponse;
          }
          if (networkResponse && networkResponse.status === 304) {
            return caches.match(request).then((cached) => cached || networkResponse);
          }
          return networkResponse;
        })
        .catch(() => caches.match(request))
    );
  }
});
