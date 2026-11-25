/* LeakLens Security Portal — Production Offline Service Worker */
const APP_SHELL_CACHE = "leaklens-shell-v1";
const RUNTIME_CACHE = "leaklens-runtime-v1";

const PRECACHE_ASSETS = [
  "/",
  "/index.html",
  "/manifest.json",
  "/icons/icon-192x192.png",
  "/icons/icon-512x512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(APP_SHELL_CACHE)
      .then((cache) =>
        Promise.allSettled(
          PRECACHE_ASSETS.map((assetUrl) =>
            cache.add(new Request(assetUrl, { cache: "reload" }))
          )
        )
      )
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  const validCaches = new Set([APP_SHELL_CACHE, RUNTIME_CACHE]);
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.map((key) => {
            if (!validCaches.has(key)) {
              return caches.delete(key);
            }
            return Promise.resolve();
          })
        )
      )
      .then(() => self.clients.claim())
  );
});

async function networkFirstWithCacheFallback(request) {
  const url = new URL(request.url);
  const targetCache =
    url.pathname === "/" ||
    url.pathname === "/index.html" ||
    url.pathname === "/manifest.json" ||
    url.pathname.startsWith("/assets/") ||
    url.pathname.startsWith("/icons/")
      ? APP_SHELL_CACHE
      : RUNTIME_CACHE;

  try {
    const networkResponse = await fetch(request);
    if (networkResponse && networkResponse.ok && (networkResponse.type === "basic" || networkResponse.type === "cors")) {
      const cache = await caches.open(targetCache);
      cache.put(request, networkResponse.clone()).catch(() => {});
    }
    return networkResponse;
  } catch {
    const cachedMatch = await caches.match(request);
    if (cachedMatch) {
      return cachedMatch;
    }

    if (request.mode === "navigate") {
      const appShellFallback =
        (await caches.match("/index.html")) || (await caches.match("/"));
      if (appShellFallback) {
        return appShellFallback;
      }
    }

    return new Response(
      JSON.stringify({
        status: "offline_cached",
        message: "Offline fallback active; no cached copy found for this asset.",
      }),
      {
        status: 503,
        statusText: "Service Unavailable",
        headers: { "Content-Type": "application/json" },
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

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return;
  }

  // Only intercept same-origin app shell & runtime requests cleanly
  if (parsedUrl.origin !== self.location.origin) {
    return;
  }

  // Never serve stale sw.js from cache during update checks
  if (parsedUrl.pathname === "/sw.js") {
    return;
  }

  event.respondWith(networkFirstWithCacheFallback(request));
});
