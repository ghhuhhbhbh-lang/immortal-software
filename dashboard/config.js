/* Shared Immortal endpoints — loader + dashboard both read these. */
(function (w) {
  var isFile = typeof location !== 'undefined' && location.protocol === 'file:';
  var isLocal = typeof location !== 'undefined' &&
    (location.hostname === 'localhost' || location.hostname === '127.0.0.1');

  // Production: set window.IMMORTAL_API before this script, or rely on same-origin /api proxy.
  w.IMMORTAL_API = w.IMMORTAL_API ||
    (isFile || isLocal ? 'http://127.0.0.1:3000' : (location.origin || 'https://api.immortal.local'));

  try {
    w.IMMORTAL_PORTAL = w.IMMORTAL_PORTAL || new URL('../dashboard/index.html', document.baseURI).href;
  } catch {
    w.IMMORTAL_PORTAL = '../dashboard/index.html';
  }
  w.IMMORTAL_ASSETS = w.IMMORTAL_ASSETS || {
    logo: 'assets/logo2.png',
    bg: 'assets/bg.png',
  };
  w.IMMORTAL_SECURE_STORAGE = w.IMMORTAL_SECURE_STORAGE !== false;
})(window);
