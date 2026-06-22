/* site.js — 22DIV portfolio — hamburger nav + theme toggle + particle field */
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

    initParticleField();
    initTypewriter();
  });

  function setIcon(btn) {
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    btn.textContent = isLight ? '☽' : '☀';
    btn.title = isLight ? 'dark mode' : 'light mode';
  }

  /* ── TYPEWRITER ── */
  function initTypewriter() {
    var el = document.getElementById('typewriter');
    if (!el) return;
    var lines = [
      'for Cheyanne.',
      'I won\'t ever stop.',
      'I\'ll discover something.',
      'there\'s no amount of poison you can put in my soul',
      'that will ever make me stop loving you.',
      'this is the only path I have ever discovered',
      'that wasn\'t illegal or had no prospect.',
      'every morning I wake up I research, I run tests.',
      'one day I\'m gonna have my name on published cybersecurity reports',
      'and then you will never have to struggle or have fear again.',
      'I only fear failure. I don\'t care if u don\'t love me.',
      'I don\'t want you to die.',
    ];
    var lineIdx = 0, charIdx = 0, deleting = false;
    var typeSpeed = 55, deleteSpeed = 25, holdTime = 3500, pauseAfterDelete = 800;

    function tick() {
      var line = lines[lineIdx];
      if (!deleting) {
        charIdx++;
        el.textContent = line.substring(0, charIdx);
        if (charIdx >= line.length) {
          setTimeout(function() { deleting = true; tick(); }, holdTime);
          return;
        }
        setTimeout(tick, typeSpeed + Math.random() * 40);
      } else {
        charIdx--;
        el.textContent = line.substring(0, charIdx);
        if (charIdx <= 0) {
          deleting = false;
          lineIdx = (lineIdx + 1) % lines.length;
          setTimeout(tick, pauseAfterDelete);
          return;
        }
        setTimeout(tick, deleteSpeed);
      }
    }

    setTimeout(tick, 1500);
  }

  /* ── PARTICLE CONSTELLATION ── */
  function initParticleField() {
    var canvas = document.getElementById('particle-field');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var W, H, particles = [], mouse = { x: -9999, y: -9999 };
    var CONNECT_DIST = 120;
    var PARTICLE_COUNT = 80;
    var heartPhase = 0;
    var heartActive = false;
    var heartTimer = 0;
    var heartInterval = 12000;
    var heartDuration = 4000;
    var heartFade = 0;
    var globalPulse = 0;
    var startTime = Date.now();

    function resize() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = Math.max(window.innerHeight, 600);
    }
    resize();
    window.addEventListener('resize', resize);

    window.addEventListener('mousemove', function(e) {
      mouse.x = e.clientX;
      mouse.y = e.clientY + window.scrollY;
    });

    function heartShape(t) {
      var x = 16 * Math.pow(Math.sin(t), 3);
      var y = -(13 * Math.cos(t) - 5 * Math.cos(2*t) - 2 * Math.cos(3*t) - Math.cos(4*t));
      return { x: x, y: y };
    }

    function Particle(i) {
      this.x = Math.random() * W;
      this.y = Math.random() * H;
      this.homeX = this.x;
      this.homeY = this.y;
      this.vx = (Math.random() - 0.5) * 0.4;
      this.vy = (Math.random() - 0.5) * 0.4;
      this.size = Math.random() * 1.5 + 0.5;
      this.idx = i;
      this.heartX = 0;
      this.heartY = 0;
      this.alpha = Math.random() * 0.5 + 0.3;
      this.baseAlpha = this.alpha;
      this.breathOffset = Math.random() * Math.PI * 2;
      this.hue = Math.random() < 0.7 ? 140 : (Math.random() < 0.5 ? 45 : 185);
    }

    for (var i = 0; i < PARTICLE_COUNT; i++) {
      particles.push(new Particle(i));
    }

    function assignHeartTargets() {
      var cx = W / 2;
      var cy = H * 0.35;
      var scale = Math.min(W, H) * 0.012;
      for (var i = 0; i < particles.length; i++) {
        var t = (i / particles.length) * Math.PI * 2;
        var h = heartShape(t);
        particles[i].heartX = cx + h.x * scale;
        particles[i].heartY = cy + h.y * scale;
      }
    }

    function draw(now) {
      ctx.clearRect(0, 0, W, H);

      var elapsed = now - startTime;
      heartTimer += 16;

      globalPulse = Math.sin(elapsed * 0.003) * 0.15 + 1;
      var heartbeat = Math.pow(Math.sin(elapsed * 0.006), 16) * 0.3;
      globalPulse += heartbeat;

      if (heartTimer > heartInterval && !heartActive) {
        heartActive = true;
        heartTimer = 0;
        heartFade = 0;
        assignHeartTargets();
      }
      if (heartActive) {
        heartPhase += 16;
        if (heartPhase < 1500) {
          heartFade = Math.min(1, heartPhase / 1500);
        } else if (heartPhase > heartDuration - 1500) {
          heartFade = Math.max(0, (heartDuration - heartPhase) / 1500);
        }
        if (heartPhase > heartDuration) {
          heartActive = false;
          heartPhase = 0;
          heartFade = 0;
        }
      }

      for (var i = 0; i < particles.length; i++) {
        var p = particles[i];

        if (heartActive && heartFade > 0) {
          var tx = p.heartX;
          var ty = p.heartY;
          p.x += (tx - p.x) * 0.02 * heartFade;
          p.y += (ty - p.y) * 0.02 * heartFade;
          p.vx *= (1 - 0.02 * heartFade);
          p.vy *= (1 - 0.02 * heartFade);
        }

        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) { p.x = 0; p.vx *= -1; }
        if (p.x > W) { p.x = W; p.vx *= -1; }
        if (p.y < 0) { p.y = 0; p.vy *= -1; }
        if (p.y > H) { p.y = H; p.vy *= -1; }

        var dx = mouse.x - p.x;
        var dy = (mouse.y) - p.y;
        var dist = Math.sqrt(dx*dx + dy*dy);
        if (dist < 150 && dist > 0) {
          var force = (150 - dist) / 150 * 0.008;
          p.vx += dx * force;
          p.vy += dy * force;
        }

        var speed = Math.sqrt(p.vx*p.vx + p.vy*p.vy);
        if (speed > 1.5) {
          p.vx *= 0.98;
          p.vy *= 0.98;
        }

        p.alpha = p.baseAlpha + Math.sin(elapsed * 0.002 + p.breathOffset) * 0.15;
        var drawSize = p.size * globalPulse;

        var hueStr;
        if (heartActive && heartFade > 0.3) {
          hueStr = '340';
          p.alpha = Math.min(1, p.alpha + heartFade * 0.4);
        } else {
          hueStr = String(p.hue);
        }

        ctx.beginPath();
        ctx.arc(p.x, p.y, drawSize, 0, Math.PI * 2);
        ctx.fillStyle = 'hsla(' + hueStr + ', 100%, 65%, ' + p.alpha + ')';
        ctx.fill();

        if (drawSize > 1) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, drawSize * 2.5, 0, Math.PI * 2);
          ctx.fillStyle = 'hsla(' + hueStr + ', 100%, 65%, ' + (p.alpha * 0.1) + ')';
          ctx.fill();
        }
      }

      ctx.lineWidth = 0.5;
      for (var i = 0; i < particles.length; i++) {
        for (var j = i + 1; j < particles.length; j++) {
          var dx = particles[i].x - particles[j].x;
          var dy = particles[i].y - particles[j].y;
          var dist = Math.sqrt(dx*dx + dy*dy);
          if (dist < CONNECT_DIST) {
            var lineAlpha = (1 - dist/CONNECT_DIST) * 0.15;
            if (heartActive && heartFade > 0.3) {
              ctx.strokeStyle = 'hsla(340, 80%, 60%, ' + (lineAlpha + heartFade * 0.1) + ')';
            } else {
              ctx.strokeStyle = 'hsla(140, 80%, 50%, ' + lineAlpha + ')';
            }
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      if (heartActive && heartFade > 0.5) {
        ctx.save();
        ctx.globalAlpha = heartFade * 0.08;
        ctx.font = '10px monospace';
        ctx.fillStyle = '#ff2d8a';
        ctx.textAlign = 'center';
        ctx.fillText('C', W/2, H * 0.35 + Math.min(W,H) * 0.012 * 20 + 15);
        ctx.restore();
      }

      requestAnimationFrame(draw);
    }

    requestAnimationFrame(draw);
  }
})();
