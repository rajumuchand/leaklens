/* LeakLens Security Portal — Mobile & Offline Service Worker */
const APP_SHELL_CACHE = "leaklens-pwa-shell-v3";
const RUNTIME_CACHE = "leaklens-pwa-runtime-v3";

const PRECACHE_URLS = [
  "/index.html",
  "/manifest.json",
  "/icons/apple-touch-icon.png",
  "/icons/icon-192x192.png",
  "/icons/icon-512x512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(APP_SHELL_CACHE)
      .then((cache) =>
        Promise.allSettled([
          ...PRECACHE_URLS.map((url) =>
            cache.add(new Request(url, { cache: "reload" }))
          ),
          cache.add(
            new Request("/", {
              headers: { Accept: "text/html" },
              cache: "reload"
            })
          )
        ])
      )
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  const allowed = new Set([APP_SHELL_CACHE, RUNTIME_CACHE]);
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.map((key) => {
            if (!allowed.has(key)) {
              return caches.delete(key);
            }
            return Promise.resolve();
          })
        )
      )
      .then(() => self.clients.claim())
  );
});

async function networkFirstWithOfflineFallback(request) {
  const url = new URL(request.url);
  const cacheName =
    url.pathname === "/" ||
    url.pathname === "/index.html" ||
    url.pathname === "/manifest.json" ||
    url.pathname.startsWith("/icons/")
      ? APP_SHELL_CACHE
      : RUNTIME_CACHE;

  try {
    const networkResponse = await fetch(request);
    if (
      networkResponse &&
      networkResponse.ok &&
      (networkResponse.type === "basic" || networkResponse.type === "cors")
    ) {
      const contentType = networkResponse.headers.get("content-type") || "";
      // Never overwrite cached HTML shell for "/" with API JSON responses
      if (!(url.pathname === "/" && contentType.includes("application/json"))) {
        const cache = await caches.open(cacheName);
        cache.put(request, networkResponse.clone()).catch(() => {});
      }
    }
    return networkResponse;
  } catch {
    const cached = await caches.match(request);
    if (cached) {
      return cached;
    }

    if (request.mode === "navigate") {
      const htmlFallback =
        (await caches.match("/index.html")) ||
        (await caches.match("/", { ignoreSearch: true }));
      if (htmlFallback) {
        return htmlFallback;
      }
    }

    return new Response(
      JSON.stringify({
        status: "offline_cached",
        error: "Offline fallback active; requested resource not yet cached."
      }),
      {
        status: 503,
        statusText: "Service Unavailable",
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  let parsedUrl;
  try {
    parsedUrl = new URL(request.url);
  } catch {
    return;
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") return;
  if (parsedUrl.origin !== self.location.origin) return;
  if (parsedUrl.pathname === "/sw.js") return;

  event.respondWith(networkFirstWithOfflineFallback(request));
});
