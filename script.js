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

  /* ---------- cursor tilt on the demo panel ---------- */
  var heroDemo = document.querySelector('.hero-demo');
  var tiltEl = document.querySelector('.demo-tilt');
  if (heroDemo && tiltEl && !reduceMotion && canHover) {
    heroDemo.addEventListener('pointermove', function (e) {
      var rect = heroDemo.getBoundingClientRect();
      var px = (e.clientX - rect.left) / rect.width - 0.5;
      var py = (e.clientY - rect.top) / rect.height - 0.5;
      tiltEl.style.transform =
        'rotateY(' + (px * 3.4).toFixed(2) + 'deg) rotateX(' + (-py * 2.6).toFixed(2) + 'deg)';
    });
    heroDemo.addEventListener('pointerleave', function () {
      tiltEl.style.transform = '';
    });
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

  /* ---------- redaction micro-story in the secret leakage card ---------- */
  var redactTarget = document.querySelector('.redact-target');
  var redactText = document.querySelector('.redact-text');
  var redactPlayed = false;
  var RAW_KEY = 'AKIA2E51X9MT7EXAMPLE';
  var REDACTED = redactText ? redactText.textContent : '';

  /* The card ships with the sealed value in markup; the raw key only ever
     appears as the opening beat of the animation, so a missed observer can
     never leave a "leaked" key standing on screen. */
  function playRedaction() {
    if (redactPlayed || !redactTarget || reduceMotion) return;
    redactPlayed = true;
    redactTarget.classList.add('raw');
    redactText.textContent = RAW_KEY;
    setTimeout(function () { redactTarget.classList.add('covering'); }, 900);
    setTimeout(function () {
      redactText.textContent = REDACTED;
      redactTarget.classList.remove('raw');
    }, 1450);
    setTimeout(function () { redactTarget.classList.add('uncover'); }, 1600);
  }

  /* ---------- scroll reveal (IntersectionObserver, no scroll listeners) ----------
     Sections are visible by default; the observer only ADDS an entrance
     animation. If a callback lands late or never (fast momentum scroll,
     headless render), the content stands un-animated instead of blank. */
  if (!reduceMotion && 'IntersectionObserver' in window) {
    var revealObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var el = entry.target;
        /* Animate only a genuine entrance from below; when the observer
           fires late the section is already on screen — re-hiding it to
           replay the entrance would flash the content out. */
        if (entry.boundingClientRect.top > window.innerHeight * 0.45) {
          el.classList.add('in');
        }
        if (el.classList.contains('metrics')) runCountUps(el);
        if (el.id === 'threats') playRedaction();
        revealObserver.unobserve(el);
      });
    }, { threshold: 0.15 });

    document.querySelectorAll('.reveal').forEach(function (el) {
      revealObserver.observe(el);
    });
  }

  /* ---------- hero demo: typed command, wall sweep, sanitized output ---------- */
  var demoTimers = [];
  function schedule(fn, ms) { demoTimers.push(setTimeout(fn, ms)); }

  var demo = heroDemo;
  if (demo && !reduceMotion) {
    demo.classList.add('anim');
    var rawLines = Array.prototype.slice.call(demo.querySelectorAll('.term-raw .tl'));
    var cleanLines = Array.prototype.slice.call(demo.querySelectorAll('.term-clean .tl'));
    var cmdEl = demo.querySelector('.type-cmd');
    var cmdText = cmdEl ? cmdEl.textContent : '';
    var tokEl = demo.querySelector('.tok-n');
    var tokTarget = tokEl ? parseInt(tokEl.textContent.replace(/\D/g, ''), 10) : 0;
    /* a phone scroller gives the hero ~2 seconds; the choreography must
       land its payoff inside that window, so small screens play it fast */
    var quick = window.matchMedia('(max-width: 768px)').matches;
    var T = quick
      ? { first: 350, pre: 140, perChar: 28, raw: 130, gap: 180, wall: 380, clean: 110 }
      : { first: 900, pre: 250, perChar: 55, raw: 240, gap: 250, wall: 550, clean: 190 };

    function countTokens() {
      if (!tokEl) return;
      var duration = 650;
      var start = null;
      function frame(now) {
        if (start === null) start = now;
        var p = Math.min((now - start) / duration, 1);
        var eased = 1 - Math.pow(1 - p, 3);
        tokEl.textContent = Math.round(tokTarget * eased);
        if (p < 1) requestAnimationFrame(frame);
      }
      requestAnimationFrame(frame);
    }

    function playDemo(initial) {
      demoTimers.forEach(clearTimeout);
      demoTimers = [];
      rawLines.concat(cleanLines).forEach(function (l) { l.classList.remove('on'); });
      demo.classList.remove('wall-up');
      if (cmdEl) { cmdEl.textContent = ''; cmdEl.classList.remove('typing'); }
      if (tokEl) tokEl.textContent = '0';

      var t = initial ? T.first : 250; /* first run waits for the frames to rise */

      if (cmdEl) {
        schedule(function () {
          rawLines[0].classList.add('on');
          cmdEl.classList.add('typing');
        }, t);
        for (var i = 0; i < cmdText.length; i++) {
          (function (i) {
            schedule(function () {
              cmdEl.textContent = cmdText.slice(0, i + 1);
              if (i === cmdText.length - 1) cmdEl.classList.remove('typing');
            }, t + T.pre + i * T.perChar);
          })(i);
        }
        t += T.pre + cmdText.length * T.perChar + T.gap;
      }

      rawLines.slice(1).forEach(function (line, i) {
        schedule(function () { line.classList.add('on'); }, t + i * T.raw);
      });
      t += (rawLines.length - 1) * T.raw + T.gap;

      schedule(function () { demo.classList.add('wall-up'); }, t);
      t += T.wall;

      cleanLines.forEach(function (line, i) {
        schedule(function () {
          line.classList.add('on');
          if (line.querySelector('.tok-n')) countTokens();
        }, t + i * T.clean);
      });
    }

    playDemo(true);

    var boundary = demo.querySelector('.boundary');
    if (boundary) {
      boundary.addEventListener('click', function () { playDemo(false); });
      boundary.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          playDemo(false);
        }
      });
    }
  }

  /* ---------- bronze spotlight follows the cursor on threat cards ---------- */
  if (!reduceMotion && canHover) {
    document.querySelectorAll('.threat-card').forEach(function (card) {
      card.addEventListener('pointermove', function (e) {
        var rect = card.getBoundingClientRect();
        card.style.setProperty('--mx', (e.clientX - rect.left) + 'px');
        card.style.setProperty('--my', (e.clientY - rect.top) + 'px');
      });
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

  /* ---------- install tabs ---------- */
  var tabs = document.querySelectorAll('.tab');
  var panels = document.querySelectorAll('.tab-panel');

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      var name = tab.getAttribute('data-tab');
      tabs.forEach(function (t) {
        var active = t === tab;
        t.classList.toggle('active', active);
        t.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      panels.forEach(function (p) {
        var show = p.getAttribute('data-panel') === name;
        p.classList.toggle('active', show);
        if (show) { p.removeAttribute('hidden'); } else { p.setAttribute('hidden', ''); }
      });
    });
  });
})();
