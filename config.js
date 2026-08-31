/* Immortal Key Manager — sealed API channel (not user-editable) */
(function (w) {
  // Same authority as Loader config — do not expose an endpoint field in UI.
  var sealed = ['h','t','t','p',':','/','/','1','2','7','.','0','.','0','.','1',':','3','0','0','0'].join('');
  Object.defineProperty(w, 'IMMORTAL_API', {
    value: sealed,
    writable: false,
    configurable: false,
    enumerable: false,
  });
  w.IMMORTAL_KM = '2.4.0';
})(window);
