// labs/kwlinks.js — colour-coded keyword hyperlinks to field manual chapters
(function () {
  'use strict';

  const READER = '../books/reader.html?b=';

  // [term, book-slug, css-class]
  // Longer phrases first — prevents "XOR" from matching before "XOR cipher"
  const KW = [
    // RED — exploit primitives / mitigations
    ['hardware breakpoint', '04_MITIGATIONS',        'kw-red'],
    ['process injection',   '07_EXPLOIT_PRIMITIVES', 'kw-red'],
    ['reverse shell',       '15_POST_EXPLOITATION',  'kw-green'],
    ['PATH hijacking',      '15_POST_EXPLOITATION',  'kw-green'],
    ['DLL hijacking',       '15_POST_EXPLOITATION',  'kw-green'],
    ['lateral movement',    '15_POST_EXPLOITATION',  'kw-green'],
    ['firewall evasion',    '17_NETWORK_WARFARE',    'kw-cyan'],
    ['dead drop',           '17_NETWORK_WARFARE',    'kw-cyan'],
    ['TCP socket',          '17_NETWORK_WARFARE',    'kw-cyan'],
    ['social engineering',  '22_OSINT_SOCIAL_ENGINEERING', 'kw-purple'],
    ['spear phishing',      '22_OSINT_SOCIAL_ENGINEERING', 'kw-purple'],
    ['Google Dorking',      '22_OSINT_SOCIAL_ENGINEERING', 'kw-purple'],
    ['VirtualAllocEx',      '07_EXPLOIT_PRIMITIVES', 'kw-red'],
    ['WriteProcessMemory',  '07_EXPLOIT_PRIMITIVES', 'kw-red'],
    ['CreateRemoteThread',  '07_EXPLOIT_PRIMITIVES', 'kw-red'],
    ['shellcode',           '07_EXPLOIT_PRIMITIVES', 'kw-red'],
    ['HWBP',                '04_MITIGATIONS',        'kw-red'],
    ['AMSI',                '04_MITIGATIONS',        'kw-red'],
    ['stager',              '07_EXPLOIT_PRIMITIVES', 'kw-red'],
    ['ROP',                 '07_EXPLOIT_PRIMITIVES', 'kw-red'],
    // AMBER — crypto / evasion
    ['obfuscation',         '18_CRYPTOGRAPHY_EVASION', 'kw-amber'],
    ['XOR',                 '18_CRYPTOGRAPHY_EVASION', 'kw-amber'],
    ['AES',                 '18_CRYPTOGRAPHY_EVASION', 'kw-amber'],
    ['cipher',              '18_CRYPTOGRAPHY_EVASION', 'kw-amber'],
    ['packing',             '18_CRYPTOGRAPHY_EVASION', 'kw-amber'],
    ['evasion',             '18_CRYPTOGRAPHY_EVASION', 'kw-amber'],
    ['encoding',            '18_CRYPTOGRAPHY_EVASION', 'kw-amber'],
    // GREEN — persistence / post-ex
    ['persistence',         '15_POST_EXPLOITATION',  'kw-green'],
    ['registry',            '15_POST_EXPLOITATION',  'kw-green'],
    ['HKCU',                '15_POST_EXPLOITATION',  'kw-green'],
    ['beacon',              '17_NETWORK_WARFARE',    'kw-cyan'],
    // CYAN — networking / C2
    ['C2',                  '17_NETWORK_WARFARE',    'kw-cyan'],
    // BLUE — Windows / AD
    ['PowerShell',          '20_ACTIVE_DIRECTORY',   'kw-blue'],
    ['LOLBins',             '20_ACTIVE_DIRECTORY',   'kw-blue'],
    ['BloodHound',          '20_ACTIVE_DIRECTORY',   'kw-blue'],
    ['Kerberoasting',       '20_ACTIVE_DIRECTORY',   'kw-blue'],
    // PURPLE — OSINT / social
    ['phishing',            '22_OSINT_SOCIAL_ENGINEERING', 'kw-purple'],
    ['pretexting',          '22_OSINT_SOCIAL_ENGINEERING', 'kw-purple'],
    ['persona',             '22_OSINT_SOCIAL_ENGINEERING', 'kw-purple'],
    ['OSINT',               '22_OSINT_SOCIAL_ENGINEERING', 'kw-purple'],
  ];

  const COLORS = {
    'kw-red':    '#ff6666',
    'kw-amber':  '#ffb000',
    'kw-green':  '#00cc33',
    'kw-cyan':   '#00e5ff',
    'kw-blue':   '#4488ff',
    'kw-purple': '#b060ff',
  };

  const TITLES = {
    '04_MITIGATIONS':             'Ch.04 — Mitigations & Bypasses',
    '07_EXPLOIT_PRIMITIVES':      'Ch.07 — Exploit Primitives',
    '15_POST_EXPLOITATION':       'Ch.15 — Post-Exploitation',
    '17_NETWORK_WARFARE':         'Ch.17 — Network Warfare',
    '18_CRYPTOGRAPHY_EVASION':    'Ch.18 — Cryptography & Evasion',
    '20_ACTIVE_DIRECTORY':        'Ch.20 — Active Directory Warfare',
    '22_OSINT_SOCIAL_ENGINEERING':'Ch.22 — OSINT & Social Engineering',
  };

  // Inject styles once
  const css = Object.entries(COLORS).map(([cls, col]) =>
    `a.kwlink.${cls}{color:${col};border-bottom-color:${col}33;}`
  ).join('');
  const style = document.createElement('style');
  style.textContent = `
    a.kwlink{
      text-decoration:none;
      border-bottom:1px dashed;
      cursor:pointer;
      font-weight:bold;
      transition:opacity .15s;
    }
    a.kwlink:hover{opacity:.7;}
    ${css}
  `;
  document.head.appendChild(style);

  // Build regex: sort by term length desc so multi-word phrases match before single words
  const sorted = [...KW].sort((a,b) => b[0].length - a[0].length);
  const escapedTerms = sorted.map(([t]) =>
    t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );
  const pattern = new RegExp('\\b(' + escapedTerms.join('|') + ')\\b', 'gi');

  // Map from lowercased term to [slug, cls]
  const termMap = new Map(sorted.map(([t, slug, cls]) => [t.toLowerCase(), [slug, cls]]));

  // DOM elements to scan — prose only, not code
  const PROSE = [
    '.metaphor',
    '.nomenclature td:last-child',
    '.lesson-header > p',
    '.task-desc',
  ];

  // Per-lesson first-occurrence guard: key = lessonId + ':' + termLower
  const linked = new Set();

  function getLesson(node) {
    let el = node.parentElement;
    while (el) {
      if (el.classList && el.classList.contains('lesson')) return el.id || '_';
      el = el.parentElement;
    }
    return '_global';
  }

  function isInsideBlocked(node) {
    let el = node.parentElement;
    while (el) {
      const tag = el.tagName;
      if (!tag) break;
      const t = tag.toUpperCase();
      if (['SCRIPT','STYLE','A','CODE','PRE','TEXTAREA','BUTTON'].includes(t)) return true;
      if (el.classList && el.classList.contains('code-ref')) return true;
      el = el.parentElement;
    }
    return false;
  }

  function processTextNode(node) {
    if (isInsideBlocked(node)) return;
    const text = node.nodeValue;
    if (!text || !pattern.test(text)) return;
    pattern.lastIndex = 0;

    const lessonId = getLesson(node);
    const frag = document.createDocumentFragment();
    let last = 0;
    let m;
    pattern.lastIndex = 0;
    let replaced = false;

    while ((m = pattern.exec(text)) !== null) {
      const raw = m[0];
      const key = lessonId + ':' + raw.toLowerCase();
      const entry = termMap.get(raw.toLowerCase());
      if (!entry || linked.has(key)) continue;

      linked.add(key);
      replaced = true;

      if (m.index > last) {
        frag.appendChild(document.createTextNode(text.slice(last, m.index)));
      }

      const a = document.createElement('a');
      const [slug, cls] = entry;
      a.className = 'kwlink ' + cls;
      a.href = READER + slug;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.title = '📖 ' + (TITLES[slug] || slug.replace(/_/g,' '));
      a.textContent = raw;
      frag.appendChild(a);

      last = m.index + raw.length;
    }

    if (!replaced) return;
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    node.parentNode.replaceChild(frag, node);
  }

  function walkTextNodes(root) {
    // Snapshot all text nodes before modifying the DOM
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
    const nodes = [];
    let n;
    while ((n = walker.nextNode())) nodes.push(n);
    nodes.forEach(processTextNode);
  }

  function run() {
    PROSE.forEach(sel => {
      document.querySelectorAll(sel).forEach(walkTextNodes);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();
