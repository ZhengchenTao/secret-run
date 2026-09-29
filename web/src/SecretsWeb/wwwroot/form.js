// Write forms (create / edit / delete): submitted with fetch, carrying the antiforgery token and the custom header — the same
// protections as the decrypt endpoints. Values only live in the form and the request body; never in localStorage or the URL.
(function () {
  'use strict';

  function token(form) {
    var el = form.querySelector('input[name="__RequestVerificationToken"]');
    return el ? el.value : '';
  }

  function status(form, msg) {
    var el = form.querySelector('.status');
    if (el) el.textContent = msg;
  }

  document.querySelectorAll('form[data-api]').forEach(function (form) {
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();

      var typed = form.querySelector('input[data-must-equal]');
      if (typed && typed.value !== typed.getAttribute('data-must-equal')) {
        status(form, 'The entry name you typed does not match');
        return;
      }

      var button = form.querySelector('button[type="submit"]');
      if (button) button.disabled = true;
      status(form, 'Submitting…');

      var data = new FormData(form);
      data.delete('__RequestVerificationToken');

      fetch(form.getAttribute('action'), {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'RequestVerificationToken': token(form), 'X-Secrets-Web': '1' },
        body: data
      }).then(function (r) {
        if (r.status === 401) { location.reload(); return; }
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok) throw new Error(j.error || ('Request failed: HTTP ' + r.status));
          location.href = j.redirect || '/';
        });
      }).catch(function (e) {
        status(form, e.message);
        if (button) button.disabled = false;
      });
    });
  });

  // New-entry page: only show the fields relevant to the selected type
  var typeSelect = document.getElementById('entry-type');
  if (typeSelect) {
    var fileOnly = document.querySelector('.file-only');
    var sync = function () {
      if (fileOnly) fileOnly.hidden = typeSelect.value !== 'file';
    };
    typeSelect.addEventListener('change', sync);
    sync();
  }
})();
