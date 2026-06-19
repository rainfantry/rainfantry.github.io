/* site.js — 22DIV portfolio — hamburger nav + theme toggle */
(function() {
  var saved = localStorage.getItem('22div-theme');
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');

  document.addEventListener('DOMContentLoaded', function() {
    var toggle = document.getElementById('navToggle');
    var links = document.getElementById('navLinks');
    if (toggle && links) {
      toggle.addEventListener('click', function() {
        var isOpen = links.classList.toggle('show');
        toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        toggle.textContent = isOpen ? '✕' : '☰';
      });
      var anchors = links.querySelectorAll('a');
      for (var i = 0; i < anchors.length; i++) {
        anchors[i].addEventListener('click', function() {
          if (window.innerWidth <= 768) {
            links.classList.remove('show');
            toggle.setAttribute('aria-expanded', 'false');
            toggle.textContent = '☰';
          }
        });
      }
    }

    var themeBtn = document.getElementById('themeToggle');
    if (themeBtn) {
      setIcon(themeBtn);
      themeBtn.addEventListener('click', function() {
        var isLight = document.documentElement.getAttribute('data-theme') === 'light';
        if (isLight) {
          document.documentElement.removeAttribute('data-theme');
          localStorage.setItem('22div-theme', 'dark');
        } else {
          document.documentElement.setAttribute('data-theme', 'light');
          localStorage.setItem('22div-theme', 'light');
        }
        setIcon(themeBtn);
      });
    }
  });

  function setIcon(btn) {
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    btn.textContent = isLight ? '☽' : '☀';
    btn.title = isLight ? 'dark mode' : 'light mode';
  }
})();
