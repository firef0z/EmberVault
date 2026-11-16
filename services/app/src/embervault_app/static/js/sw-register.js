/**
 * Service Worker Registration for PWA support
 */

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/static/service-worker.js')
      .then((reg) => {
        // SW registered
      })
      .catch((err) => {
        // SW registration failed
      });
  });
}
