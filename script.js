(function () {
  'use strict';

  document.documentElement.classList.add('js');

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var canHover = window.matchMedia('(hover: hover)').matches;

  /* gsap gate: scenes only exist when motion is allowed AND gsap loaded.
     Without html.gsap the stylesheet must render a complete static page. */
  var gsapOK = !reduceMotion &&
    typeof window.gsap !== 'undefined' &&
    typeof window.ScrollTrigger !== 'undefined';
  if (gsapOK) {
    gsap.registerPlugin(ScrollTrigger);
    document.documentElement.classList.add('gsap');
  }

  /* ---------- rising embers over the hero (canvas) ---------- */
  var emberCanvas = document.querySelector('.embers');
  if (emberCanvas && !reduceMotion && emberCanvas.getContext) {
    var ctx = emberCanvas.getContext('2d');
    var hero = emberCanvas.parentElement;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var W = 0, H = 0;
    var motes = [];
    var running = false;
    var rafId = 0;

    function sizeCanvas() {
      W = hero.clientWidth;
      H = hero.clientHeight;
      emberCanvas.width = W * dpr;
      emberCanvas.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function spawn(anywhere) {
      return {
        x: Math.random() * W,
        y: anywhere ? Math.random() * H : H + 6,
        r: 0.7 + Math.random() * 1.7,
        v: 14 + Math.random() * 22,          /* px per second, upward */
        sway: 8 + Math.random() * 18,
        phase: Math.random() * Math.PI * 2,
        alpha: 0.18 + Math.random() * 0.4
      };
    }

    function initMotes() {
      var count = Math.round(Math.min(70, Math.max(30, W / 24)));
      motes = [];
      for (var i = 0; i < count; i++) motes.push(spawn(true));
    }

    var last = 0;
    function tick(now) {
      if (!running) return;
      var dt = Math.min((now - last) / 1000, 0.05);
      last = now;
      ctx.clearRect(0, 0, W, H);
      for (var i = 0; i < motes.length; i++) {
        var m = motes[i];
        m.y -= m.v * dt;
        m.phase += dt * 0.9;
        var x = m.x + Math.sin(m.phase) * m.sway;
        /* fade near the top third, glow strongest mid-flight */
        var lifeFade = Math.max(0, Math.min(1, m.y / (H * 0.38)));
        ctx.globalAlpha = m.alpha * lifeFade;
        ctx.fillStyle = '#d9b264';
        ctx.beginPath();
        ctx.arc(x, m.y, m.r, 0, Math.PI * 2);
        ctx.fill();
        if (m.y < -8) motes[i] = spawn(false);
      }
      ctx.globalAlpha = 1;
      rafId = requestAnimationFrame(tick);
    }

    function start() {
      if (running) return;
      running = true;
      last = performance.now();
      rafId = requestAnimationFrame(tick);
    }
    function stop() {
      running = false;
      cancelAnimationFrame(rafId);
    }

    sizeCanvas();
    initMotes();

    window.addEventListener('resize', function () {
      sizeCanvas();
      initMotes();
    });

    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (entries) {
        entries[0].isIntersecting ? start() : stop();
      }, { threshold: 0 }).observe(hero);
    } else {
      start();
    }
  }

  /* ---------- metric count-ups ---------- */
  var metricsDone = false;
  function runCountUps(section) {
    if (metricsDone || reduceMotion) return;
    metricsDone = true;
    section.querySelectorAll('[data-count]').forEach(function (el) {
      var raw = el.getAttribute('data-count');
      var target = parseFloat(raw);
      var suffix = el.getAttribute('data-suffix') || '';
      var decimals = (raw.split('.')[1] || '').length;
      var duration = 1500;
      var start = null;
      function frame(now) {
        if (start === null) start = now;
        var p = Math.min((now - start) / duration, 1);
        var eased = 1 - Math.pow(1 - p, 4);
        el.textContent = (target * eased).toFixed(decimals) + suffix;
        if (p < 1) {
          requestAnimationFrame(frame);
        } else {
          el.textContent = raw + suffix; /* land exactly on the real value */
        }
      }
      requestAnimationFrame(frame);
    });
  }

  /* ---------- copy buttons ---------- */
  function flash(el, selector, message) {
    var target = selector ? el.querySelector(selector) : el;
    if (!target) return;
    var original = target.textContent;
    target.textContent = message;
    setTimeout(function () { target.textContent = original; }, 1400);
  }

  /* clipboard API with a legacy textarea fallback; the button always
     answers, even when it has to say the copy failed */
  function copyText(text, onDone, onFail) {
    function legacy() {
      try {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand('copy');
        document.body.removeChild(ta);
        if (ok) { onDone(); } else { onFail(); }
      } catch (e) {
        onFail();
      }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onDone, legacy);
    } else {
      legacy();
    }
  }

  document.querySelectorAll('[data-copy]').forEach(function (el) {
    el.addEventListener('click', function () {
      var sel = el.classList.contains('install-chip') ? '.chip-copy' : null;
      copyText(el.getAttribute('data-copy'), function () {
        flash(el, sel, 'Copied');
      }, function () {
        flash(el, sel, 'Copy failed');
      });
    });
  });
})();
