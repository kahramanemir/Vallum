(function () {
  'use strict';

  document.documentElement.classList.add('js');

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

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

  /* ---------- hero load choreography ---------- */
  if (gsapOK) {
    var heroTl = gsap.timeline({ defaults: { ease: 'power3.out' } });
    heroTl
      .from('.inscription', { opacity: 0, scale: 1.04, duration: 1.4, ease: 'power2.out' })
      .from('.hero h1', { y: 28, opacity: 0, duration: 0.8 }, '-=0.9')
      .from('.hero-sub', { y: 22, opacity: 0, duration: 0.7 }, '-=0.55')
      .from('.hero-actions', { y: 18, opacity: 0, duration: 0.6 }, '-=0.45')
      .from('.descend', { opacity: 0, duration: 0.8 }, '-=0.2');

    /* inscription parallax: sinks slightly as you leave the gate.
       yPercent only — opacity belongs to the load timeline above; sharing
       the channel let the scrub capture a mid-fade start value and pin the
       inscription invisible after the first scroll */
    gsap.to('.inscription', {
      yPercent: 18, ease: 'none',
      scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: true }
    });
  }

  /* ---------- Scene I: the demonstration ---------- */
  if (gsapOK) {
    var layers = document.querySelector('.scene-demo .term-layers');
    var tokN = document.querySelector('.scene-demo .tok-n');
    if (layers) {
      var sweepState = { v: 0 };
      var mmDemo = gsap.matchMedia();
      mmDemo.add('(min-width: 900px)', function () {
        gsap.to(sweepState, {
          v: 100, ease: 'none',
          scrollTrigger: {
            trigger: '.scene-demo', start: 'top top', end: '+=1400',
            pin: true, scrub: 0.4,
            onUpdate: function (st) {
              layers.classList.toggle('sweeping', st.progress > 0.01 && st.progress < 0.99);
              if (tokN) {
                var t = Math.round(3210 - (3210 - 612) * st.progress);
                tokN.textContent = t.toLocaleString('en-US');
              }
            }
          },
          /* tween-level onUpdate: sweepState.v is interpolated per tick */
          onUpdate: function () {
            layers.style.setProperty('--sweep', String(sweepState.v));
          }
        });
      });
      /* below 900px: no pin; show the static stacked layout */
      mmDemo.add('(max-width: 899px)', function () {
        layers.removeAttribute('style');
        layers.classList.remove('sweeping');
        if (tokN) tokN.textContent = '3,210';
      });
    }
  }

  /* ---------- Scene II: six gates ---------- */
  var gatesStage = document.querySelector('.gates-stage');
  if (gatesStage && gsapOK) {
    var stations = document.querySelectorAll('.gate-station');
    var mmGates = gsap.matchMedia();
    mmGates.add('(min-width: 900px)', function () {
      gatesStage.setAttribute('data-step', '0'); /* rewind to raw for the story */
      ScrollTrigger.create({
        trigger: '.scene-gates', start: 'top top', end: '+=2600',
        pin: true, scrub: true,
        onUpdate: function (st) {
          var step = Math.min(6, Math.floor(st.progress * 6.999));
          if (gatesStage.getAttribute('data-step') !== String(step)) {
            gatesStage.setAttribute('data-step', String(step));
            stations.forEach(function (s, i) {
              s.style.opacity = (i + 1 <= step) ? '1' : '';
            });
          }
        }
      });
      return function () { gatesStage.setAttribute('data-step', '6'); };
    });
    /* below 900px html.gsap still applies; restore static detail */
    mmGates.add('(max-width: 899px)', function () {
      gatesStage.setAttribute('data-step', '6');
      var notes = document.querySelectorAll('.station-note');
      notes.forEach(function (n) { n.style.display = 'block'; });
      stations.forEach(function (s) { s.style.opacity = '1'; });
      return function () {
        notes.forEach(function (n) { n.style.display = ''; });
        stations.forEach(function (s) { s.style.opacity = ''; });
      };
    });
  }

  /* ---------- threats: evidence lines stamp in ---------- */
  if (gsapOK) {
    document.querySelectorAll('.indictment').forEach(function (ind) {
      var lines = ind.querySelectorAll('.evidence .tl');
      var targets = lines.length ? lines : ind.querySelectorAll('.big-num');
      gsap.from(targets, {
        opacity: 0, y: 10, duration: 0.45, stagger: 0.12, ease: 'power2.out',
        scrollTrigger: { trigger: ind, start: 'top 70%' }
      });
      gsap.from(ind.querySelector('.ind-head'), {
        opacity: 0, y: 24, duration: 0.7, ease: 'power3.out',
        scrollTrigger: { trigger: ind, start: 'top 75%' }
      });
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

  /* ---------- guardrail seals stamp in ---------- */
  if (gsapOK) {
    gsap.from('.seal', {
      scale: 2.2, opacity: 0, rotation: 8, duration: 0.5,
      ease: 'back.out(2.2)', stagger: 0.3, immediateRender: false,
      scrollTrigger: { trigger: '.ledger', start: 'top 72%' }
    });
  }

  /* ---------- metrics count up + motto reveal ---------- */
  var metricsSection = document.querySelector('.metrics');
  if (metricsSection && gsapOK) {
    ScrollTrigger.create({
      trigger: metricsSection, start: 'top 70%', once: true,
      onEnter: function () { runCountUps(metricsSection); }
    });
  }
  var mottoLatin = document.querySelector('.motto-latin');
  if (mottoLatin && gsapOK) {
    ScrollTrigger.create({
      trigger: '.motto', start: 'top 75%', once: true,
      onEnter: function () { mottoLatin.classList.add('in'); }
    });
  }

  /* ---------- patrol rail ---------- */
  if (gsapOK) {
    var mmPatrol = gsap.matchMedia();
    mmPatrol.add('(min-width: 1100px)', function () {
      gsap.to('.patrol-fill', {
        scaleY: 1, ease: 'none',
        scrollTrigger: { trigger: document.body, start: 'top top', end: 'bottom bottom', scrub: 0.5 }
      });
      var wpIds = ['hero', 'demo', 'threats', 'pipeline', 'guardrail', 'metrics', 'install'];
      var wps = document.querySelectorAll('.patrol .waypoint');
      wpIds.forEach(function (id, i) {
        var el = document.getElementById(id);
        var wp = wps[i];
        if (!el || !wp) return;
        /* pinned scenes are wrapped in a .pin-spacer by the earlier scene
           blocks; using it as trigger spans the full pinned duration */
        var trig = el.closest('.pin-spacer') || el;
        ScrollTrigger.create({
          trigger: trig, start: 'top 55%', end: 'bottom 45%',
          onToggle: function (st) {
            wp.classList.toggle('active', st.isActive);
            if (st.isActive) { wp.setAttribute('aria-current', 'true'); } else { wp.removeAttribute('aria-current'); }
          }
        });
      });
      return function () {
        wps.forEach(function (w) { w.classList.remove('active'); });
      };
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

  /* ---------- install method switcher ---------- */
  var methods = document.querySelectorAll('.method');
  var cmdPanels = document.querySelectorAll('.plinth-cmd');
  methods.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var name = btn.getAttribute('data-method');
      methods.forEach(function (m) {
        var active = m === btn;
        m.classList.toggle('active', active);
        m.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      cmdPanels.forEach(function (p) {
        var show = p.getAttribute('data-method-panel') === name;
        p.classList.toggle('active', show);
        if (show) { p.removeAttribute('hidden'); } else { p.setAttribute('hidden', ''); }
      });
    });
  });
})();
