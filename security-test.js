// Security + function test for Blockwatch. Run: node security-test.js
const { chromium } = require('playwright');
const http = require('http');
const fs = require('fs');
const path = require('path');

const DIR = process.argv[2] || __dirname;
const OUT = process.argv[3] || path.join(__dirname, 'security-test-screenshot.png');

// Hostile-but-plausible API response: a compromised or spoofed upstream,
// or just a server operator who put HTML in their MOTD.
const EVIL = {
  online: true, hostname: 'evil.example.com', port: 25565,
  version: '1.21.1 <img src=x onerror="window.__XSS_VERSION=1">',
  software: 'Paper',
  players: {
    online: 3, max: 20,
    list: [{ name: 'Notch' }, { name: '<img src=x onerror="window.__XSS_PLAYER=1">' }]
  },
  motd: {
    raw: ['§aWelcome §cback'],
    clean: ['Welcome back'],
    html: ['<span style="color:#55FF55">Welcome</span><img src=x onerror="window.__XSS_MOTD=1">']
  },
  icon: 'data:text/html;base64,PHNjcmlwdD53aW5kb3cuX19YU1NfSUNPTj0xPC9zY3JpcHQ+',
  eula_blocked: false
};

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.md': 'text/plain' };

const server = http.createServer((req, res) => {
  const f = path.join(DIR, req.url === '/' ? 'index.html' : req.url.split('?')[0]);
  if (!f.startsWith(DIR) || !fs.existsSync(f)) { res.writeHead(404); return res.end('nope'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream' });
  res.end(fs.readFileSync(f));
});

(async () => {
  await new Promise(r => server.listen(8099, r));
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 900, height: 1400 }, deviceScaleFactor: 2 });

  const consoleErrors = [];
  page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('pageerror', e => consoleErrors.push('PAGEERROR: ' + e.message));

  // Intercept the upstream API and serve the hostile payload.
  await page.route('**api.mcsrvstat.us**', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(EVIL) }));

  await page.goto('http://127.0.0.1:8099/', { waitUntil: 'load' });

  const results = {};

  // --- CSP present? ---
  results.csp = await page.evaluate(() =>
    !!document.querySelector('meta[http-equiv="Content-Security-Policy" i]'));

  // --- Test 1-3: XSS via untrusted API data ---
  await page.fill('#addr', 'evil.example.com');
  await page.click('#go');
  await page.waitForTimeout(1200);
  results.xss_motd = await page.evaluate(() => !!window.__XSS_MOTD);
  results.xss_player = await page.evaluate(() => !!window.__XSS_PLAYER);
  results.xss_version = await page.evaluate(() => !!window.__XSS_VERSION);
  results.icon_src = await page.evaluate(() => {
    const i = document.querySelector('.icon'); return i ? i.getAttribute('src').slice(0, 24) : null;
  });

  await page.screenshot({ path: OUT, fullPage: true });

  // --- Test 4: stored XSS via the saved-server list (attribute breakout) ---
  await page.evaluate(() => {
    try {
      localStorage.setItem('blockwatch.servers',
        JSON.stringify(["x'),window.__XSS_SAVED=1,('"]));
    } catch (e) {}
  });
  await page.reload({ waitUntil: 'load' });
  await page.click('#t-saved');
  await page.waitForTimeout(300);
  // the payload fires when the generated onclick handler is invoked
  const checkBtns = await page.$$('#srvlist .btn');
  if (checkBtns.length) { await checkBtns[0].click().catch(() => {}); await page.waitForTimeout(400); }
  results.xss_saved_list = await page.evaluate(() => !!window.__XSS_SAVED);

  // --- Test 5: does a non-JSON / garbage localStorage value break the page? ---
  await page.evaluate(() => { try { localStorage.setItem('blockwatch.servers', 'not json{'); } catch (e) {} });
  const before = consoleErrors.filter(e => /PAGEERROR/.test(e)).length;
  await page.reload({ waitUntil: 'load' });
  await page.waitForTimeout(400);
  results.breaks_on_bad_storage = consoleErrors.filter(e => /PAGEERROR/.test(e)).length > before;
  results.storage_recovered = await page.evaluate(() =>
    !!document.querySelector('#srvlist') && document.querySelectorAll('nav button').length === 3);

  // --- Test 6: is user input URL-encoded before going into the request path? ---
  let requested = null;
  page.on('request', r => { if (r.url().includes('mcsrvstat')) requested = r.url(); });
  await page.evaluate(() => { try { localStorage.removeItem('blockwatch.servers'); } catch (e) {} });
  await page.reload({ waitUntil: 'load' });
  await page.fill('#addr', 'a b/../../admin?x=1#frag');
  await page.click('#go');
  await page.waitForTimeout(800);
  results.raw_url = requested;
  results.input_validated = await page.evaluate(() =>
    /Enter a valid|not a valid|invalid/i.test(document.getElementById('out').textContent));

  // --- Test 7: rel=noopener on external links ---
  results.unsafe_target_blank = await page.evaluate(() =>
    [...document.querySelectorAll('a[target="_blank"]')]
      .filter(a => !/noopener/.test(a.rel)).map(a => a.href));

  // --- Test 8: calculator still works ---
  await page.click('#t-ram');
  results.calc_ok = await page.evaluate(() =>
    /Xmx/.test(document.getElementById('flags').textContent) &&
    document.getElementById('ram-stats').children.length === 4);

  // --- Test 9: MOTD still renders with its colours (fix must not break the feature) ---
  await page.click('#t-status');
  await page.fill('#addr', 'evil.example.com');
  await page.waitForTimeout(1700);
  await page.click('#go');
  await page.waitForTimeout(1200);
  results.motd_coloured = await page.evaluate(() => {
    const s = document.querySelectorAll('.motd span');
    return [...s].some(x => /rgb\(85, 255, 85\)/.test(x.style.color));
  });
  results.motd_text = await page.evaluate(() => {
    const m = document.querySelector('.motd'); return m ? m.textContent.trim() : null;
  });
  results.csp_violations = consoleErrors.filter(e => /Content Security Policy/i.test(e)).slice(0, 5);

  results.consoleErrors = consoleErrors.slice(0, 8);

  console.log(JSON.stringify(results, null, 2));
  await browser.close();
  server.close();
})().catch(e => { console.error('FATAL', e); process.exit(1); });
