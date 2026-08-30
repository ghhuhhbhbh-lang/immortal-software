'use strict';
/* ── Ambient audio ────────────────────────────────────────────────────────────
   A soft generative drone for the menu — slow chord swells, a low sub, filtered
   star-hiss and the occasional distant chime, all rendered live through a
   synthesised reverb. Nothing is streamed or loaded; it's pure Web Audio, so it
   costs no assets and never loops audibly.
   Toggle lives in the top-left corner and remembers its state.             */
(function () {

const btn = document.getElementById('audio-toggle');
if (!btn) return;

const STORE   = 'ip-ambient';
const VOLUME  = 0.5;          // master ceiling — deliberately gentle
let enabled   = localStorage.getItem(STORE) !== 'off';
let ctx = null, master = null, pad = null, voices = [], started = false;
let chordTimer = 0, chimeTimer = 0;

/* ── Harmony ────────────────────────────────────────────────────────────────
   Four wide, unhurried voicings that drift into each other. Low register so
   the pad sits under the UI instead of competing with it.                  */
const CHORDS = [
  [ 73.42, 110.00, 174.61, 220.00 ],  // Dm9-ish
  [ 65.41,  98.00, 164.81, 196.00 ],  // Cadd9
  [ 58.27,  87.31, 146.83, 220.00 ],  // Bb6/9
  [ 87.31, 130.81, 174.61, 261.63 ],  // Fmaj7
];
const CHIMES = [523.25, 587.33, 698.46, 783.99, 880.00, 1046.50];
let chordIx = 0;

/* Synthesised impulse response — a long, dark tail that sells "vast empty". */
function makeReverb(seconds, decay) {
  const rate = ctx.sampleRate;
  const len  = Math.floor(rate * seconds);
  const buf  = ctx.createBuffer(2, len, rate);
  for (let ch = 0; ch < 2; ch++) {
    const data = buf.getChannelData(ch);
    for (let i = 0; i < len; i++) {
      const t = i / len;
      data[i] = (Math.random() * 2 - 1) * Math.pow(1 - t, decay);
    }
  }
  const conv = ctx.createConvolver();
  conv.buffer = buf;
  return conv;
}

/* Soft noise bed — the hiss of a hull in vacuum. */
function makeNoiseBed(dest) {
  const rate = ctx.sampleRate;
  const buf  = ctx.createBuffer(1, rate * 4, rate);
  const data = buf.getChannelData(0);
  let b0 = 0, b1 = 0, b2 = 0;
  for (let i = 0; i < data.length; i++) {          // cheap pink-ish noise
    const white = Math.random() * 2 - 1;
    b0 = 0.99765 * b0 + white * 0.0990460;
    b1 = 0.96300 * b1 + white * 0.2965164;
    b2 = 0.57000 * b2 + white * 1.0526913;
    data[i] = (b0 + b1 + b2 + white * 0.1848) * 0.09;
  }
  const src = ctx.createBufferSource();
  src.buffer = buf;
  src.loop = true;

  const band = ctx.createBiquadFilter();
  band.type = 'bandpass';
  band.frequency.value = 620;
  band.Q.value = 0.6;

  const gain = ctx.createGain();
  gain.gain.value = 0.09;

  // slow sweep so the bed never sits still
  const lfo = ctx.createOscillator();
  lfo.frequency.value = 0.021;
  const lfoAmt = ctx.createGain();
  lfoAmt.gain.value = 280;
  lfo.connect(lfoAmt).connect(band.frequency);
  lfo.start();

  src.connect(band).connect(gain).connect(dest);
  src.start();
}

/* One pad voice: two slightly detuned oscillators through a breathing filter. */
function makeVoice(freq, dest) {
  const gain = ctx.createGain();
  gain.gain.value = 0;

  const filt = ctx.createBiquadFilter();
  filt.type = 'lowpass';
  filt.frequency.value = 760;
  filt.Q.value = 0.4;

  const a = ctx.createOscillator();
  a.type = 'sine';
  a.frequency.value = freq;

  const b = ctx.createOscillator();
  b.type = 'triangle';
  b.frequency.value = freq;
  b.detune.value = 7 + Math.random() * 6;

  const bGain = ctx.createGain();
  bGain.gain.value = 0.28;

  // gentle amplitude drift keeps the chord alive without a tremolo effect
  const lfo = ctx.createOscillator();
  lfo.frequency.value = 0.035 + Math.random() * 0.06;
  const lfoAmt = ctx.createGain();
  lfoAmt.gain.value = 0.055;
  lfo.connect(lfoAmt).connect(gain.gain);

  a.connect(filt);
  b.connect(bGain).connect(filt);
  filt.connect(gain).connect(dest);

  a.start(); b.start(); lfo.start();
  return { a, b, filt, gain, base: 0 };
}

/* A far-off chime, panned somewhere out in the dark. */
function chime() {
  if (!ctx || ctx.state !== 'running') return;
  const now  = ctx.currentTime;
  const freq = CHIMES[Math.floor(Math.random() * CHIMES.length)];

  const osc = ctx.createOscillator();
  osc.type = 'sine';
  osc.frequency.value = freq;

  const harm = ctx.createOscillator();
  harm.type = 'sine';
  harm.frequency.value = freq * 2.01;
  const harmGain = ctx.createGain();
  harmGain.gain.value = 0.22;

  const env = ctx.createGain();
  env.gain.setValueAtTime(0.0001, now);
  env.gain.exponentialRampToValueAtTime(0.10, now + 0.06);
  env.gain.exponentialRampToValueAtTime(0.0001, now + 5.5);

  osc.connect(env);
  harm.connect(harmGain).connect(env);

  if (ctx.createStereoPanner) {
    const panNode = ctx.createStereoPanner();
    panNode.pan.value = (Math.random() * 2 - 1) * 0.75;
    env.connect(panNode).connect(pad);
  } else {
    env.connect(pad);
  }

  osc.start(now); harm.start(now);
  osc.stop(now + 6); harm.stop(now + 6);
}

/* Glide the whole pad to the next voicing — no attack, just a slow morph. */
function nextChord() {
  if (!ctx) return;
  const chord = CHORDS[chordIx % CHORDS.length];
  chordIx++;
  const now = ctx.currentTime;
  voices.forEach((v, i) => {
    const f = chord[i % chord.length];
    v.a.frequency.setTargetAtTime(f, now, 2.4);
    v.b.frequency.setTargetAtTime(f, now, 2.6);
    v.filt.frequency.setTargetAtTime(560 + Math.random() * 520, now, 3.5);
    v.gain.gain.setTargetAtTime(v.base, now, 3.0);
  });
}

function boot() {
  const AC = window.AudioContext || window.webkitAudioContext;
  if (!AC) return false;
  ctx = new AC();

  master = ctx.createGain();
  master.gain.value = 0;
  master.connect(ctx.destination);

  // everything lands in the same wash, with a little dry signal for body
  const verb = makeReverb(4.5, 2.6);
  const wet  = ctx.createGain(); wet.gain.value = 0.85;
  const dry  = ctx.createGain(); dry.gain.value = 0.5;

  pad = ctx.createGain();
  pad.connect(verb).connect(wet).connect(master);
  pad.connect(dry).connect(master);

  const chordGains = [0.16, 0.13, 0.10, 0.075];
  voices = CHORDS[0].map((f, i) => {
    const v = makeVoice(f, pad);
    v.base = chordGains[i];
    return v;
  });

  // sub drone, felt more than heard
  const sub = ctx.createOscillator();
  sub.type = 'sine';
  sub.frequency.value = 36.71;
  const subGain = ctx.createGain();
  subGain.gain.value = 0.10;
  sub.connect(subGain).connect(master);
  sub.start();

  makeNoiseBed(pad);
  nextChord();

  chordTimer = setInterval(nextChord, 14000);
  chimeTimer = setInterval(() => { if (Math.random() < 0.6) chime(); }, 7000);
  started = true;
  return true;
}

function applyVolume() {
  if (!ctx || !master) return;
  const target = enabled ? VOLUME : 0;
  master.gain.setTargetAtTime(target, ctx.currentTime, enabled ? 1.6 : 0.5);
}

function ensureRunning() {
  if (!enabled) return;
  if (!started && !boot()) return;
  if (ctx.state === 'suspended') ctx.resume().then(applyVolume, () => {});
  applyVolume();
}

/* Autoplay policies want a gesture — take the first one we're given. */
function armGesture() {
  const go = () => { ensureRunning(); };
  ['pointerdown', 'keydown', 'mousemove', 'wheel'].forEach(ev =>
    window.addEventListener(ev, go, { once: true, passive: true })
  );
}

/* ── Toggle UI ─────────────────────────────────────────────────────────────── */
function paint() {
  btn.classList.toggle('muted', !enabled);
  btn.setAttribute('aria-pressed', String(enabled));
  btn.title = enabled ? 'Ambient audio — on' : 'Ambient audio — off';
}

btn.addEventListener('click', () => {
  enabled = !enabled;
  localStorage.setItem(STORE, enabled ? 'on' : 'off');
  paint();
  if (enabled) ensureRunning();
  else applyVolume();
});

paint();
armGesture();
// try straight away in case the host allows unprompted playback (WebView2 does)
ensureRunning();

})();
