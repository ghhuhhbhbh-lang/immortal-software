(function (w) {
  var host = (typeof location !== 'undefined' && location.hostname) || '';
  var isFile = typeof location !== 'undefined' && location.protocol === 'file:';
  var isVirtual = host === 'immortal.loader';
  var isLocal = host === 'localhost' || host === '127.0.0.1' || host === '' || isVirtual;

  w.IMMORTAL_API = w.IMMORTAL_API ||
    (isFile || isLocal ? 'http://127.0.0.1:3000' : (location.origin || 'https://api.immortal.local'));

  try {
    w.IMMORTAL_LOADER = w.IMMORTAL_LOADER || new URL('../Emulator Loader GUI/index.html', document.baseURI).href;
    w.IMMORTAL_ADMIN = w.IMMORTAL_ADMIN || new URL('../dashboard/index.html', document.baseURI).href;
  } catch {
    w.IMMORTAL_LOADER = '../Emulator Loader GUI/index.html';
    w.IMMORTAL_ADMIN = '../dashboard/index.html';
  }
})(window);
