let registrationPromise = null;

/**
 * Registers /sw.js cleanly in production or HTTPS environments.
 * Guarded against duplicate registrations and silent when unsupported or offline.
 */
export function registerServiceWorker() {
  if (typeof window === "undefined" || !("serviceWorker" in navigator)) {
    return null;
  }

  const isProd = Boolean(
    typeof import.meta !== "undefined" && import.meta.env && import.meta.env.PROD
  );
  const isHttps = window.location.protocol === "https:";

  if (!isProd && !isHttps) {
    return null;
  }

  if (registrationPromise) {
    return registrationPromise;
  }

  registrationPromise = navigator.serviceWorker
    .register("/sw.js", { scope: "/" })
    .then((registration) => {
      registration.addEventListener("updatefound", () => {
        const installingWorker = registration.installing;
        if (!installingWorker) return;
        installingWorker.addEventListener("statechange", () => {
          if (
            installingWorker.state === "installed" &&
            navigator.serviceWorker.controller
          ) {
            // New SW cached and ready to take over on next navigation
          }
        });
      });
      return registration;
    })
    .catch(() => {
      // Gracefully ignore SW registration failures in sandboxed or offline browsers
      return null;
    });

  return registrationPromise;
}

export function unregisterServiceWorker() {
  if (typeof window === "undefined" || !("serviceWorker" in navigator)) {
    return Promise.resolve(false);
  }
  return navigator.serviceWorker.ready
    .then((registration) => registration.unregister())
    .catch(() => false);
}
