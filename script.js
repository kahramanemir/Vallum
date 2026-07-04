(function () {
  'use strict';

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- scroll reveal (IntersectionObserver, no scroll listeners) ---------- */
  if (!reduceMotion && 'IntersectionObserver' in window) {
    var revealObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          revealObserver.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15 });

    document.querySelectorAll('.reveal').forEach(function (el) {
      revealObserver.observe(el);
    });
  } else {
    document.querySelectorAll('.reveal').forEach(function (el) {
      el.classList.add('in');
    });
  }

  /* ---------- hero demo: raw output types in, wall rises, clean output follows ---------- */
  var demo = document.querySelector('.hero-demo');
  if (demo && !reduceMotion) {
    demo.classList.add('anim');
    var rawLines = demo.querySelectorAll('.term-raw .tl');
    var cleanLines = demo.querySelectorAll('.term-clean .tl');
    var delay = 350;

    rawLines.forEach(function (line, i) {
      setTimeout(function () { line.classList.add('on'); }, delay + i * 260);
    });

    var wallAt = delay + rawLines.length * 260 + 250;
    setTimeout(function () { demo.classList.add('wall-up'); }, wallAt);

    cleanLines.forEach(function (line, i) {
      setTimeout(function () { line.classList.add('on'); }, wallAt + 550 + i * 200);
    });
  }

  /* ---------- copy buttons ---------- */
  function flash(el, selector) {
    var target = selector ? el.querySelector(selector) : el;
    if (!target) return;
    var original = target.textContent;
    target.textContent = 'Copied';
    setTimeout(function () { target.textContent = original; }, 1400);
  }

  document.querySelectorAll('[data-copy]').forEach(function (el) {
    el.addEventListener('click', function () {
      var text = el.getAttribute('data-copy');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          flash(el, el.classList.contains('install-chip') ? '.chip-copy' : null);
        });
      }
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
