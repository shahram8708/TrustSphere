const CACHE_VERSION = "v1";
const STATIC_CACHE = "trustsphere-static-v1";
const PAGES_CACHE = "trustsphere-pages-v1";
const FONT_CACHE = "trustsphere-fonts-v1";
const ALL_CACHES = [STATIC_CACHE, PAGES_CACHE, FONT_CACHE];

const STATIC_ASSETS_TO_PRECACHE = [
  "/static/css/base.css",
  "/static/css/components.css",
  "/static/css/admin.css",
  "/static/css/portal.css",
  "/static/js/main.js",
  "/static/js/pwa-install.js",
  "/static/js/risk-gauge.js",
  "/static/js/admin-dashboard.js",
  "/static/js/session-timeline.js",
  "/static/js/policy-builder.js",
  "/static/js/device-fp.js",
  "/static/js/behavioural-sdk.js",
  "/static/img/icon-192.png",
  "/static/img/icon-512.png",
  "/static/img/logo.svg",
  "/static/manifest.json"
];

const PUBLIC_PAGES_TO_PRECACHE = [
  "/",
  "/about",
  "/features",
  "/compliance",
  "/pricing",
  "/contact",
  "/auth/login",
  "/offline"
];

const CDN_RESOURCES_TO_CACHE = [
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css",
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js",
  "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css",
  "https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js",
  "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap"
];

const CDN_HOSTNAMES = new Set([
  "cdn.jsdelivr.net",
  "fonts.googleapis.com",
  "fonts.gstatic.com"
]);

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    try {
      const staticCache = await caches.open(STATIC_CACHE);
      try {
        await staticCache.addAll(STATIC_ASSETS_TO_PRECACHE);
      } catch (error) {
        console.warn("SW: Static pre-cache skipped for one or more assets:", error);
      }

      const pagesCache = await caches.open(PAGES_CACHE);
      try {
        await pagesCache.addAll(PUBLIC_PAGES_TO_PRECACHE);
      } catch (error) {
        console.warn("SW: Page pre-cache skipped for one or more pages:", error);
      }

      try {
        await Promise.all(
          CDN_RESOURCES_TO_CACHE.map(async (url) => {
            try {
              const response = await fetch(url, { mode: "no-cors" });
              if (response && (response.ok || response.type === "opaque")) {
                await staticCache.put(url, response.clone());
              }
            } catch (error) {
              console.warn("SW: Failed to cache CDN resource:", url);
            }
          })
        );
      } catch (error) {
        console.warn("SW: CDN pre-cache skipped:", error);
      }
    } finally {
      await self.skipWaiting();
    }
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const cacheNames = await caches.keys();
    await Promise.all(
      cacheNames
        .filter((name) => !ALL_CACHES.includes(name))
        .map((name) => {
          console.log("SW: Deleting old cache:", name);
          return caches.delete(name);
        })
    );
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") {
    return;
  }

  const url = new URL(event.request.url);

  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/auth/logout")) {
    return;
  }

  if (url.pathname.startsWith("/static/") || CDN_HOSTNAMES.has(url.hostname)) {
    event.respondWith(cacheFirst(event.request, STATIC_CACHE));
    return;
  }

  if (isPublicPage(url.pathname)) {
    event.respondWith(staleWhileRevalidate(event.request, PAGES_CACHE));
    return;
  }

  if (
    url.pathname.startsWith("/portal/")
    || url.pathname.startsWith("/admin/")
    || url.pathname.startsWith("/auth/")
  ) {
    event.respondWith(networkFirst(event.request, PAGES_CACHE));
    return;
  }

  event.respondWith(networkFirst(event.request, PAGES_CACHE));
});

self.addEventListener("message", (event) => {
  if (!event.data || !event.data.type) {
    return;
  }

  if (event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
    return;
  }

  if (event.data.type === "GET_VERSION" && event.ports && event.ports[0]) {
    event.ports[0].postMessage({ version: CACHE_VERSION });
    return;
  }

  if (event.data.type === "CLEAR_CACHE") {
    event.waitUntil((async () => {
      await Promise.all(
        ALL_CACHES.map(async (cacheName) => {
          const cache = await caches.open(cacheName);
          const requests = await cache.keys();
          await Promise.all(requests.map((request) => cache.delete(request)));
        })
      );
      if (event.ports && event.ports[0]) {
        event.ports[0].postMessage({ cleared: true });
      }
    })());
  }
});

function isPublicPage(pathname) {
  return (
    pathname === "/"
    || pathname.startsWith("/about")
    || pathname.startsWith("/features")
    || pathname.startsWith("/compliance")
    || pathname.startsWith("/pricing")
    || pathname.startsWith("/contact")
    || pathname.startsWith("/demo")
    || pathname.startsWith("/offline")
  );
}

function isHtmlRequest(request) {
  const accept = request.headers.get("Accept") || "";
  return request.mode === "navigate" || accept.includes("text/html");
}

function isCacheableResponse(response) {
  return response && (response.ok || response.type === "opaque");
}

async function cacheFirst(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);

  if (cached) {
    fetch(request)
      .then((response) => {
        if (isCacheableResponse(response)) {
          cache.put(request, response.clone());
        }
      })
      .catch(() => {});
    return cached;
  }

  try {
    const response = await fetch(request);
    if (isCacheableResponse(response)) {
      await cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    if (isHtmlRequest(request)) {
      return getOfflineFallback();
    }
    return new Response("", {
      status: 503,
      statusText: "Offline",
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
}

async function staleWhileRevalidate(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);

  const freshResponse = fetch(request)
    .then((response) => {
      if (isCacheableResponse(response)) {
        cache.put(request, response.clone());
      }
      return response;
    })
    .catch(() => null);

  if (cached) {
    freshResponse.catch(() => {});
    return cached;
  }

  const response = await freshResponse;
  if (response) {
    return response;
  }
  return getOfflineFallback();
}

async function networkFirst(request, cacheName) {
  const cache = await caches.open(cacheName);
  try {
    const response = await Promise.race([
      fetch(request),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error("timeout")), 5000);
      })
    ]);

    if ([301, 302, 307, 308].includes(response.status)) {
      return response;
    }

    if (response.ok) {
      await cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    const cached = await cache.match(request);
    if (cached) {
      const headers = new Headers(cached.headers);
      headers.set("X-TrustSphere-Cached", "true");
      const body = await cached.blob();
      return new Response(body, {
        status: cached.status,
        statusText: cached.statusText,
        headers
      });
    }
    return getOfflineFallback();
  }
}

async function getOfflineFallback() {
  const cache = await caches.open(PAGES_CACHE);
  const cachedOfflinePage = await cache.match("/offline");
  if (cachedOfflinePage) {
    return cachedOfflinePage;
  }

  const offlineLinks = PUBLIC_PAGES_TO_PRECACHE
    .filter((path) => path !== "/offline")
    .map((path) => `<li><a href="${path}">${path === "/" ? "Home" : path.slice(1)}</a></li>`)
    .join("");

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>You are offline | TrustSphere</title>
  <style>
    :root {
      color-scheme: light;
      --navy: #0B1F4E;
      --gold: #C9A84C;
      --teal: #006D77;
      --light: #F8F9FA;
      --muted: #6C757D;
    }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 24px;
      font-family: Inter, system-ui, sans-serif;
      background: var(--light);
      color: #1A1A2E;
    }
    main {
      width: min(100%, 560px);
      padding: 32px;
      border: 1px solid #E0E0E0;
      border-radius: 8px;
      background: white;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
      text-align: center;
    }
    svg {
      width: 72px;
      height: 72px;
      margin-bottom: 16px;
    }
    h1 {
      color: var(--navy);
      margin: 0 0 12px;
    }
    p {
      color: var(--muted);
      line-height: 1.6;
    }
    ul {
      margin: 20px auto;
      padding-left: 24px;
      text-align: left;
      width: fit-content;
    }
    a {
      color: var(--teal);
      font-weight: 600;
    }
    button {
      border: 0;
      border-radius: 6px;
      padding: 12px 18px;
      background: var(--gold);
      color: var(--navy);
      font-weight: 700;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <main>
    <svg viewBox="0 0 64 64" role="img" aria-label="TrustSphere shield">
      <path d="M32 4c12 7 22 8 28 8v19c0 20-12 34-28 43C16 65 4 51 4 31V12c6 0 16-1 28-8z" fill="#C9A84C"/>
      <path d="M32 12c8 4 14 5 20 6v13c0 14-8 24-20 31C20 55 12 45 12 31V18c6-1 12-2 20-6z" fill="#006D77"/>
      <path d="M22 24h20M32 24v24" fill="none" stroke="#FFFFFF" stroke-width="5" stroke-linecap="round"/>
    </svg>
    <h1>You are offline</h1>
    <p>TrustSphere requires a connection for live security monitoring. The following pages are available offline:</p>
    <ul>${offlineLinks}</ul>
    <button type="button" onclick="location.reload()">Retry connection</button>
  </main>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
