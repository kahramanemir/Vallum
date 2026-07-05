(function () {
  'use strict';

  /* signals CSS that JS is live; all animation gating is scoped to html.js */
  document.documentElement.classList.add('js');

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- scroll reveal (IntersectionObserver, no scroll listeners) ---------- */
  var metricsDone = false;

  function runCountUps(section) {
    if (metricsDone || reduceMotion) return;
    metricsDone = true;
    section.querySelectorAll('[data-count]').forEach(function (el) {
      var target = parseFloat(el.getAttribute('data-count'));
      var suffix = el.getAttribute('data-suffix') || '';
      var decimals = (el.getAttribute('data-count').split('.')[1] || '').length;
      var duration = 1500;
      var start = null;
      function frame(now) {
        if (start === null) start = now;
        var p = Math.min((now - start) / duration, 1);
        var eased = 1 - Math.pow(1 - p, 4);
        el.textContent = (target * eased).toFixed(decimals) + suffix;
        if (p < 1) requestAnimationFrame(frame);
      }
      requestAnimationFrame(frame);
    });
  }

  if (!reduceMotion && 'IntersectionObserver' in window) {
    var revealObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          if (entry.target.classList.contains('metrics')) runCountUps(entry.target);
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

  /* ---------- hero demo: command types, wall rises, clean output follows ---------- */
  var demo = document.querySelector('.hero-demo');
  if (demo && !reduceMotion) {
    demo.classList.add('anim');
    var rawLines = Array.prototype.slice.call(demo.querySelectorAll('.term-raw .tl'));
    var cleanLines = Array.prototype.slice.call(demo.querySelectorAll('.term-clean .tl'));
    var cmdEl = demo.querySelector('.type-cmd');
    var cmdText = cmdEl ? cmdEl.textContent : '';
    var t = 900; /* wait for the terminal frames to rise first */

    /* line 0 carries the typed command */
    if (cmdEl) {
      cmdEl.textContent = '';
      setTimeout(function () {
        rawLines[0].classList.add('on');
        cmdEl.classList.add('typing');
      }, t);
      var perChar = 55;
      for (var i = 0; i < cmdText.length; i++) {
        (function (i) {
          setTimeout(function () {
            cmdEl.textContent = cmdText.slice(0, i + 1);
            if (i === cmdText.length - 1) cmdEl.classList.remove('typing');
          }, t + 250 + i * perChar);
        })(i);
      }
      t += 250 + cmdText.length * perChar + 300;
    }

    rawLines.slice(1).forEach(function (line, i) {
      setTimeout(function () { line.classList.add('on'); }, t + i * 240);
    });
    t += (rawLines.length - 1) * 240 + 250;

    setTimeout(function () { demo.classList.add('wall-up'); }, t);
    t += 550;

    cleanLines.forEach(function (line, i) {
      setTimeout(function () { line.classList.add('on'); }, t + i * 190);
    });
  }

  /* ---------- bronze spotlight follows the cursor on threat cards ---------- */
  if (!reduceMotion && window.matchMedia('(hover: hover)').matches) {
    document.querySelectorAll('.threat-card').forEach(function (card) {
      card.addEventListener('pointermove', function (e) {
        var rect = card.getBoundingClientRect();
        card.style.setProperty('--mx', (e.clientX - rect.left) + 'px');
        card.style.setProperty('--my', (e.clientY - rect.top) + 'px');
      });
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
