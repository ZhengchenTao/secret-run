// secrets-web: values are only fetched by POST after a click; shown values are re-masked after 30 seconds; copy never shows the value on the page.
(function () {
  'use strict';
  var REMASK_MS = 30000;
  var MASK = '••••••••';

  function token() {
    var el = document.querySelector('input[name="__RequestVerificationToken"]');
    return el ? el.value : '';
  }

  function status(msg) {
    var el = document.getElementById('status');
    if (el) el.textContent = msg;
  }

  function post(url, data) {
    var body = new URLSearchParams(data);
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'RequestVerificationToken': token(), 'X-Secrets-Web': '1' },
      body: body
    }).then(function (r) {
      if (r.status === 401) { location.reload(); throw new Error('Session expired'); }
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || ('Request failed: HTTP ' + r.status));
        return j;
      });
    });
  }

  document.querySelectorAll('ul.fields').forEach(function (list) {
    var path = list.getAttribute('data-path');
    list.querySelectorAll('li.field').forEach(function (li) {
      var field = li.getAttribute('data-field');
      var valueEl = li.querySelector('.fvalue');
      var timer = null;

      function remask() {
        valueEl.textContent = MASK;
        valueEl.classList.add('masked');
        timer = null;
      }

      li.querySelector('.js-show').addEventListener('click', function () {
        if (timer) { clearTimeout(timer); remask(); return; }
        post('/api/field', { path: path, field: field, mode: 'show' }).then(function (j) {
          valueEl.textContent = j.value;
          valueEl.classList.remove('masked');
          timer = setTimeout(remask, REMASK_MS);
          status('');
        }).catch(function (e) { status(e.message); });
      });

      li.querySelector('.js-copy').addEventListener('click', function () {
        post('/api/field', { path: path, field: field, mode: 'copy' }).then(function (j) {
          if (!navigator.clipboard) throw new Error('Clipboard is not available here (HTTPS is required)');
          return navigator.clipboard.writeText(j.value);
        }).then(function () {
          status(field + ' copied');
        }).catch(function (e) { status(e.message); });
      });
    });
  });

  document.querySelectorAll('div.file').forEach(function (box) {
    var path = box.getAttribute('data-path');
    var pre = box.querySelector('.filetext');
    box.querySelector('.js-file').addEventListener('click', function () {
      if (!pre.hidden) { pre.textContent = ''; pre.hidden = true; return; }
      post('/api/file', { path: path }).then(function (j) {
        if (j.isText) {
          pre.textContent = j.text;
          pre.hidden = false;
          status('');
        } else {
          status('Not displayable UTF-8 text or larger than 256 KB (' + j.size + ' bytes); please download it.');
        }
      }).catch(function (e) { status(e.message); });
    });
  });

  // Favorites: only changes the server-side favorites.json, never touches secrets. The button flips optimistically and flips back with a message on failure.
  document.querySelectorAll('.js-fav').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var on = btn.getAttribute('data-on') !== '1';
      btn.disabled = true;
      post('/api/favorite', { path: btn.getAttribute('data-path'), on: on ? '1' : '0' }).then(function (j) {
        var now = !!j.favorite;
        btn.setAttribute('data-on', now ? '1' : '0');
        btn.setAttribute('aria-pressed', now ? 'true' : 'false');
        btn.textContent = now ? '★' : '☆';
        status(now ? 'Added to favorites; it is listed first' : 'Removed from favorites');
      }).catch(function (e) { status(e.message); }).then(function () { btn.disabled = false; });
    });
  });
})();
