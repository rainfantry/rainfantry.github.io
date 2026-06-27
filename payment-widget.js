/* payment-widget.js — 22DIV Stripe payment panel
   Self-contained. Drop <script src="payment-widget.js"></script> anywhere.
   Company: Occupation Force Callsign GSW Pty Ltd | ABN 50 692 429 397 | ACN 692 429 397 */
(function() {
  var STRIPE_KEY = 'pk_live_51SOog7S5K1Ttf6KaHTIbEAiN80J2FHk7l1alno8IR7bliBd0gcOSqjpFmGQ1DXOKMMZkD7ec7nz6ewJhxuyW9C4z00y6JxsrH6';
  var BTN_BUNDLE  = 'buy_btn_1Tmp4iS5K1Ttf6KaIUlvp1xr';
  var BTN_MONTHLY = 'buy_btn_1Tmp9SS5K1Ttf6KaxgbBvxcw';
  var WISE_URL    = 'https://wise.com/pay/r/iGdeLuD93vCb4U8';
  var SALES_URL   = 'https://rainfantry.github.io/22nd-survey-division/#pricing';

  var CSS = [
    /* toggle */
    '#_22pw-t{position:fixed;bottom:1.4rem;right:1.4rem;z-index:10000;background:#0a2a0a;',
    'border:2px solid #2a7a2a;color:#4adc6a;font-family:monospace;font-size:.68rem;',
    'font-weight:700;letter-spacing:.14em;padding:.75rem 1.2rem;cursor:pointer;',
    'display:block;animation:_22pwp 2.2s infinite;white-space:nowrap;}',
    '#_22pw-t:hover{background:#0f400f;color:#6aff8a;border-color:#3aaa3a;}',
    '@keyframes _22pwp{0%,100%{box-shadow:0 0 0 0 rgba(42,122,42,0);}55%{box-shadow:0 0 0 8px rgba(42,122,42,.18);}}',
    '@media(max-width:420px){#_22pw-t{font-size:.58rem;padding:.55rem .9rem;bottom:.8rem;right:.8rem;}}',
    /* panel */
    '#_22pw-p{display:none;position:fixed;bottom:5.2rem;right:1.4rem;z-index:9999;',
    'width:320px;background:#010f01;border:1px solid #1a6a1a;',
    'box-shadow:0 0 40px rgba(0,0,0,.9);font-family:monospace;}',
    '#_22pw-p.open{display:block;}',
    '@media(max-width:500px){#_22pw-p{right:.5rem;left:.5rem;width:auto;bottom:4.8rem;}}',
    /* panel inner */
    '#_22pw-h{background:#020f02;border-bottom:1px solid #0d3a0d;padding:.9rem 1rem;',
    'display:flex;justify-content:space-between;align-items:flex-start;}',
    '#_22pw-x{background:none;border:none;color:#4adc6a;cursor:pointer;font-size:1.1rem;',
    'font-family:monospace;padding:0;line-height:1;flex-shrink:0;margin-left:.5rem;}',
    '#_22pw-b{padding:.9rem 1rem;}',
    '#_22pw-b stripe-buy-button{display:block;width:100%;margin-bottom:.9rem;}',
    '#_22pw-or{text-align:center;font-size:.44rem;color:#2a5a2a;letter-spacing:.18em;margin:.2rem 0 .8rem;}',
    '#_22pw-wise{display:block;text-align:center;border-top:1px solid #0a2a0a;',
    'color:#2a8a6a;font-size:.56rem;letter-spacing:.12em;text-decoration:none;',
    'padding:.7rem 1rem;margin-top:.4rem;}',
    '#_22pw-wise:hover{color:#4adcaa;background:#020f02;}',
    '#_22pw-info{font-size:.4rem;color:#1a5a1a;letter-spacing:.08em;line-height:1.8;',
    'border-top:1px solid #051505;padding:.7rem 1rem;}'
  ].join('');

  function init() {
    /* Load Stripe once */
    if (!document.querySelector('script[src*="buy-button"]')) {
      var s = document.createElement('script');
      s.async = true;
      s.src = 'https://js.stripe.com/v3/buy-button.js';
      document.head.appendChild(s);
    }

    var style = document.createElement('style');
    style.textContent = CSS;
    document.head.appendChild(style);

    /* Panel */
    var panel = document.createElement('div');
    panel.id = '_22pw-p';
    panel.innerHTML =
      '<div id="_22pw-h">' +
        '<div>' +
          '<div style="font-size:.42rem;letter-spacing:.24em;color:#2a6a2a;margin-bottom:.3rem;">// 22ND SURVEY DIVISION</div>' +
          '<div style="font-size:.84rem;color:#4adc6a;font-weight:700;letter-spacing:.04em;margin-bottom:.25rem;">OFFENSIVE SECURITY COURSE</div>' +
          '<div style="font-size:.46rem;color:#3a6a3a;letter-spacing:.06em;">Occupation Force Callsign GSW Pty Ltd</div>' +
          '<div style="font-size:.4rem;color:#2a5a2a;letter-spacing:.04em;">ABN 50 692 429 397 &nbsp;·&nbsp; ACN 692 429 397 &nbsp;·&nbsp; Sydney AU</div>' +
        '</div>' +
        '<button id="_22pw-x">&#x2715;</button>' +
      '</div>' +
      '<div id="_22pw-b">' +
        '<div style="font-size:.44rem;color:#3a7a3a;letter-spacing:.14em;text-align:center;margin-bottom:.4rem;">FULL BUNDLE — A$247.50 ONE-TIME</div>' +
        '<stripe-buy-button' +
          ' buy-button-id="' + BTN_BUNDLE + '"' +
          ' publishable-key="' + STRIPE_KEY + '">' +
        '</stripe-buy-button>' +
        '<a id="_22pw-wise" href="' + WISE_URL + '" target="_blank" rel="noopener">' +
          'INTERNATIONAL? PAY A$247.50 VIA WISE &rarr;' +
        '</a>' +
        '<div id="_22pw-or">— OR SUBSCRIBE —</div>' +
        '<div style="font-size:.44rem;color:#3a7a3a;letter-spacing:.14em;text-align:center;margin-bottom:.4rem;">MONTHLY — A$21.99/MONTH</div>' +
        '<stripe-buy-button' +
          ' buy-button-id="' + BTN_MONTHLY + '"' +
          ' publishable-key="' + STRIPE_KEY + '">' +
        '</stripe-buy-button>' +
      '</div>' +
      '<div id="_22pw-info">' +
        'Secure checkout via Stripe &nbsp;|&nbsp; AUD pricing &nbsp;|&nbsp; Receipt emailed<br>' +
        'Access delivered within 24h of confirmed payment &nbsp;|&nbsp; gwu0738@gmail.com' +
      '</div>';

    /* Toggle button */
    var toggle = document.createElement('button');
    toggle.id = '_22pw-t';
    toggle.innerHTML = 'BUY NOW &nbsp;&mdash;&nbsp; A$247.50 &rarr;';

    document.body.appendChild(panel);
    document.body.appendChild(toggle);

    toggle.addEventListener('click', function() {
      var open = panel.classList.toggle('open');
      toggle.innerHTML = open
        ? 'CLOSE &nbsp;&#x2715;'
        : 'BUY NOW &nbsp;&mdash;&nbsp; A$247.50 &rarr;';
    });

    document.getElementById('_22pw-x').addEventListener('click', function() {
      panel.classList.remove('open');
      toggle.innerHTML = 'BUY NOW &nbsp;&mdash;&nbsp; A$247.50 &rarr;';
    });

    /* Close on outside click */
    document.addEventListener('click', function(e) {
      if (!panel.contains(e.target) && e.target !== toggle) {
        panel.classList.remove('open');
        toggle.innerHTML = 'BUY NOW &nbsp;&mdash;&nbsp; A$247.50 &rarr;';
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
