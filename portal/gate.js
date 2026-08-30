/* Gate config — HASH ONLY. Never put plaintext user/pass here.
 * Rotate with: node portal/set-gate-pass.mjs "NewPass"
 */
(function (w) {
  w.IMMORTAL_GATE = {
    salt: 'immortal.gate.v3',
    hash: '1b7c4e1413eb51999bde8e7fe951040e693dfd51caa11e17981ec4c90f09f003',
    maxAttempts: 5,
    lockMs: 15 * 60 * 1000,
    sessionMs: 4 * 60 * 60 * 1000,
  };
})(window);
