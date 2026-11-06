/* Blockwatch - Minecraft server toolkit
 * Security notes: every value that reaches the DOM is written with textContent or
 * as a validated attribute. There is no innerHTML in this file, and no inline
 * event handlers in index.html, so the page runs under a CSP with no 'unsafe-inline'.
 */
(function () {
  'use strict';

  var API = 'https://api.mcsrvstat.us';
  var STORE_KEY = 'blockwatch.servers';
  var MAX_SAVED = 20;
  var MIN_GAP_MS = 1500;   // client-side throttle, we do not hammer a free API
  var TIMEOUT_MS = 12000;
  var MAX_ICON_BYTES = 256 * 1024;

  var $ = function (id) { return document.getElementById(id); };
  var lastLookup = 0;

  /* ------------------------------------------------------------------ *
   * Small DOM helpers. Everything is textContent; nothing is parsed as HTML.
   * ------------------------------------------------------------------ */
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function stat(k, v) {
    var box = el('div', 'stat');
    box.appendChild(el('div', 'k', k));
    box.appendChild(el('div', 'v', v));
    return box;
  }
  function message(parent, kind, text) {
    clear(parent);
    parent.appendChild(el('div', 'msg ' + kind, text));
  }

  /* ------------------------------------------------------------------ *
   * Input validation. The address is user-controlled and goes into a URL
   * path, so it is validated against a strict hostname/IPv4 grammar first
   * and percent-encoded second. This blocks path traversal (../), query
   * and fragment injection, and whitespace.
   * ------------------------------------------------------------------ */
  var LABEL = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
  var IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

  function validAddress(raw) {
    if (typeof raw !== 'string') return null;
    var s = raw.trim();
    if (!s || s.length > 263) return null;

    var host = s, port = null;
    var m = /^(.+):(\d{1,5})$/.exec(s);
    if (m) {
      host = m[1];
      port = parseInt(m[2], 10);
      if (!(port >= 1 && port <= 65535)) return null;
    }
    if (!host || host.length > 253) return null;

    if (IPV4.test(host)) {
      var octets = host.split('.');
      for (var i = 0; i < 4; i++) {
        if (octets[i].length > 3 || parseInt(octets[i], 10) > 255) return null;
      }
    } else {
      var parts = host.split('.');
      for (var j = 0; j < parts.length; j++) {
        if (!LABEL.test(parts[j])) return null;
      }
    }
    return port ? host + ':' + port : host;
  }

  /* ------------------------------------------------------------------ *
   * MOTD rendering. The API also returns a pre-built motd.html, but that
   * is attacker-controlled markup from a third party, so it is ignored.
   * We parse the raw section-sign codes ourselves and emit styled spans
   * whose text is set with textContent.
   * ------------------------------------------------------------------ */
  var MC_COLOR = {
    '0': '#000000', '1': '#0000AA', '2': '#00AA00', '3': '#00AAAA',
    '4': '#AA0000', '5': '#AA00AA', '6': '#FFAA00', '7': '#AAAAAA',
    '8': '#555555', '9': '#5555FF', 'a': '#55FF55', 'b': '#55FFFF',
    'c': '#FF5555', 'd': '#FF55FF', 'e': '#FFFF55', 'f': '#FFFFFF'
  };

  function motdFragment(lines) {
    var frag = document.createDocumentFragment();
    for (var li = 0; li < lines.length; li++) {
      if (typeof lines[li] !== 'string') continue;
      if (li > 0) frag.appendChild(document.createElement('br'));

      var line = lines[li].slice(0, 400);
      var style = { color: '#AAAAAA', bold: false, italic: false, under: false, strike: false };
      var buf = '';

      var flush = function () {
        if (!buf) return;
        var span = document.createElement('span');
        span.textContent = buf;               // never parsed as markup
        span.style.color = style.color;       // only ever one of our 16 literals
        if (style.bold) span.style.fontWeight = 'bold';
        if (style.italic) span.style.fontStyle = 'italic';
        var deco = [];
        if (style.under) deco.push('underline');
        if (style.strike) deco.push('line-through');
        if (deco.length) span.style.textDecoration = deco.join(' ');
        frag.appendChild(span);
        buf = '';
      };

      for (var i = 0; i < line.length; i++) {
        var ch = line[i];
        if ((ch === '§' || ch === '&') && i + 1 < line.length) {
          var code = line[i + 1].toLowerCase();
          if (ch === '&' && !/[0-9a-fk-or]/.test(code)) { buf += ch; continue; }
          if (MC_COLOR[code]) {
            flush();
            style.color = MC_COLOR[code];
            style.bold = style.italic = style.under = style.strike = false;
            i++; continue;
          }
          if (code === 'l') { flush(); style.bold = true; i++; continue; }
          if (code === 'o') { flush(); style.italic = true; i++; continue; }
          if (code === 'n') { flush(); style.under = true; i++; continue; }
          if (code === 'm') { flush(); style.strike = true; i++; continue; }
          if (code === 'r') {
            flush();
            style = { color: '#AAAAAA', bold: false, italic: false, under: false, strike: false };
            i++; continue;
          }
          if (code === 'k') { i++; continue; }   // obfuscated: drop the marker, keep text
        }
        buf += ch;
      }
      flush();
    }
    return frag;
  }

  /* ------------------------------------------------------------------ *
   * Server icon. The API hands back a data: URI. An unchecked data: URI is
   * a script-execution sink, so only a well-formed base64 PNG is accepted.
   * ------------------------------------------------------------------ */
  var PNG_DATA_URI = /^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/;
  function safeIcon(uri) {
    if (typeof uri !== 'string') return null;
    if (uri.length > MAX_ICON_BYTES) return null;
    return PNG_DATA_URI.test(uri) ? uri : null;
  }

  /* ------------------------------------------------------------------ *
   * Status lookup
   * ------------------------------------------------------------------ */
  function lookup() {
    var out = $('out');
    var typed = $('addr').value;
    var addr = validAddress(typed);

    if (!addr) {
      message(out, 'err', 'That is not a valid server address. Use a hostname like ' +
        'play.example.com or an IP like 1.2.3.4, optionally with :port.');
      return;
    }

    var now = Date.now();
    if (now - lastLookup < MIN_GAP_MS) {
      message(out, 'warn', 'Slow down a second before checking again.');
      return;
    }
    lastLookup = now;

    var bedrock = $('edition').value === 'bedrock';
    var url = API + (bedrock ? '/bedrock/3/' : '/3/') + encodeURIComponent(addr);

    var btn = $('go');
    btn.disabled = true;
    btn.textContent = 'Checking…';
    message(out, 'info', 'Querying ' + addr + '…');

    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, TIMEOUT_MS);

    fetch(url, { signal: ctl.signal, referrerPolicy: 'no-referrer', mode: 'cors' })
      .then(function (r) {
        if (!r.ok) throw new Error('The status API returned ' + r.status + '.');
        return r.json();
      })
      .then(function (d) {
        if (!d || typeof d !== 'object') throw new Error('The status API sent an unreadable response.');
        render(d, addr);
      })
      .catch(function (e) {
        message(out, 'err', e && e.name === 'AbortError'
          ? 'The lookup timed out. The API may be busy, or the server is very slow to respond.'
          : 'Lookup failed. ' + (e && e.message ? e.message : 'Check your connection and try again.'));
      })
      .then(function () {
        clearTimeout(timer);
        btn.disabled = false;
        btn.textContent = 'Check';
      });
  }

  function render(d, addr) {
    var out = $('out');
    clear(out);

    var head = el('div', 'head');

    if (!d.online) {
      var offPill = el('span', 'pill off');
      offPill.appendChild(el('span', 'dot'));
      offPill.appendChild(document.createTextNode('Offline'));
      head.appendChild(offPill);
      head.appendChild(el('span', 'host', addr + ' is not responding.'));
      out.appendChild(head);
      return;
    }

    var icon = safeIcon(d.icon);
    if (icon) {
      var img = document.createElement('img');
      img.className = 'icon';
      img.src = icon;
      img.alt = '';                 // decorative; alt text would be attacker-controlled
      img.referrerPolicy = 'no-referrer';
      head.appendChild(img);
    }

    var right = el('div');
    var onPill = el('span', 'pill on');
    onPill.appendChild(el('span', 'dot'));
    onPill.appendChild(document.createTextNode('Online'));
    right.appendChild(onPill);
    // Prefer the address the user typed over the hostname the API echoes back.
    right.appendChild(el('div', 'host', addr));
    head.appendChild(right);
    out.appendChild(head);

    var players = (d.players && typeof d.players === 'object') ? d.players : {};
    var grid = el('div', 'grid');
    grid.appendChild(stat('Players', num(players.online) + ' / ' + num(players.max)));
    grid.appendChild(stat('Version', text(d.version, 40) || 'Unknown'));
    grid.appendChild(stat('Software', text(d.software, 30) || 'Vanilla'));
    grid.appendChild(stat('Port', num(d.port) || '25565'));
    out.appendChild(grid);

    if (d.motd && Array.isArray(d.motd.raw) && d.motd.raw.length) {
      var box = el('div', 'motd');
      box.appendChild(el('span', 'lbl', 'MOTD'));
      box.appendChild(motdFragment(d.motd.raw.slice(0, 4)));
      out.appendChild(box);
    } else if (d.motd && Array.isArray(d.motd.clean) && d.motd.clean.length) {
      var box2 = el('div', 'motd');
      box2.appendChild(el('span', 'lbl', 'MOTD'));
      box2.appendChild(el('span', null, d.motd.clean.slice(0, 4).join('\n')));
      out.appendChild(box2);
    }

    if (Array.isArray(players.list) && players.list.length) {
      var names = [];
      for (var i = 0; i < players.list.length && names.length < 60; i++) {
        var p = players.list[i];
        var nm = text(p && p.name, 32);
        if (nm) names.push(nm);
      }
      if (names.length) {
        var pbox = el('div', 'motd');
        pbox.appendChild(el('span', 'lbl', 'Players online'));
        pbox.appendChild(el('span', null, names.join(', ')));
        out.appendChild(pbox);
      }
    }

    if (d.eula_blocked) {
      out.appendChild(el('div', 'msg warn', 'Mojang has EULA-blocked this server.'));
    }
  }

  function num(v) { return (typeof v === 'number' && isFinite(v)) ? String(v) : '?'; }
  function text(v, max) { return typeof v === 'string' ? v.slice(0, max) : ''; }

  /* ------------------------------------------------------------------ *
   * RAM / JVM flag planner (all local, no network)
   * ------------------------------------------------------------------ */
  function clampInt(v, lo, hi, dflt) {
    var n = parseInt(v, 10);
    if (!isFinite(n)) return dflt;
    return Math.min(Math.max(n, lo), hi);
  }

  function calc() {
    var type = $('stype').value;
    if (!Object.prototype.hasOwnProperty.call(BASE, type)) type = 'paper';

    var players = clampInt($('players').value, 1, 60, 6);
    var mods = clampInt($('mods').value, 0, 400, 80);
    var vd = clampInt($('vd').value, 3, 16, 8);
    var hostGb = clampInt($('hostram').value, 8, 64, 16);

    $('players-v').textContent = players;
    $('mods-v').textContent = mods;
    $('vd-v').textContent = vd;

    var perMod = (type === 'forge' || type === 'fabric') ? 14 : 7;
    var mb = BASE[type] + players * 55 + mods * perMod + Math.max(0, vd - 8) * 120;
    mb = Math.round(mb / 512) * 512;
    mb = Math.min(Math.max(mb, 1024), 24576);

    var gb = (mb / 1024).toFixed(1).replace(/\.0$/, '');
    var grid = $('ram-stats');
    clear(grid);
    grid.appendChild(stat('Allocate', gb + ' GB'));
    grid.appendChild(stat('-Xmx value', mb + 'M'));
    grid.appendChild(stat('Keep free for Windows', Math.max(2, Math.round(hostGb * 0.25)) + ' GB'));
    grid.appendChild(stat('Chunks loaded', Math.round(players * Math.pow(vd * 2 + 1, 2) * 0.6).toLocaleString()));

    var warn = $('ram-warn');
    clear(warn);
    if (mb / 1024 > hostGb - 2) {
      warn.appendChild(el('div', 'msg err',
        'That is more than this PC can spare. Drop the view distance or the mod count, or add RAM.'));
    }

    $('flags').textContent = flagString(mb);
  }

  var BASE = { vanilla: 1024, paper: 1024, fabric: 1536, forge: 2048 };

  function flagString(mb) {
    var big = mb >= 12288;
    return [
      'java', '-Xms' + mb + 'M', '-Xmx' + mb + 'M',
      '-XX:+UseG1GC', '-XX:+ParallelRefProcEnabled', '-XX:MaxGCPauseMillis=200',
      '-XX:+UnlockExperimentalVMOptions', '-XX:+DisableExplicitGC', '-XX:+AlwaysPreTouch',
      '-XX:G1NewSizePercent=' + (big ? 40 : 30),
      '-XX:G1MaxNewSizePercent=' + (big ? 50 : 40),
      '-XX:G1HeapRegionSize=' + (big ? 16 : 8) + 'M',
      '-XX:G1ReservePercent=' + (big ? 15 : 20),
      '-XX:G1HeapWastePercent=5', '-XX:G1MixedGCCountTarget=4',
      '-XX:InitiatingHeapOccupancyPercent=' + (big ? 20 : 15),
      '-XX:G1MixedGCLiveThresholdPercent=90', '-XX:G1RSetUpdatingPauseTimePercent=5',
      '-XX:SurvivorRatio=32', '-XX:+PerfDisableSharedMem', '-XX:MaxTenuringThreshold=1',
      '-Dusing.aikars.flags=https://mcflags.emc.gs', '-Daikars.new.flags=true',
      '-jar', 'server.jar', '--nogui'
    ].join(' ');
  }

  function copyFlags() {
    var note = $('copied');
    var done = function (msg) {
      note.textContent = msg;
      setTimeout(function () { note.textContent = ''; }, 2000);
    };
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      return done('Press Ctrl+C to copy.');
    }
    navigator.clipboard.writeText($('flags').textContent)
      .then(function () { done('Copied'); })
      .catch(function () { done('Copy blocked — select it manually.'); });
  }

  /* ------------------------------------------------------------------ *
   * Saved servers. localStorage is treated as untrusted input: another
   * script on this origin, a browser extension, or the devtools console
   * can write anything into it, so it is parsed defensively and every
   * entry is re-validated before use.
   * ------------------------------------------------------------------ */
  function getServers() {
    var raw;
    try { raw = localStorage.getItem(STORE_KEY); }
    catch (e) { return []; }                       // private mode / storage disabled
    if (!raw) return [];

    var parsed;
    try { parsed = JSON.parse(raw); }
    catch (e) { return []; }                       // corrupt value must not break the page

    if (!Array.isArray(parsed)) return [];
    var clean = [], seen = {};
    for (var i = 0; i < parsed.length && clean.length < MAX_SAVED; i++) {
      var v = validAddress(parsed[i]);
      if (v && !Object.prototype.hasOwnProperty.call(seen, v)) { seen[v] = 1; clean.push(v); }
    }
    return clean;
  }

  function setServers(list) {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0, MAX_SAVED))); return true; }
    catch (e) { return false; }
  }

  function addServer() {
    var box = $('saved-msg');
    clear(box);
    var v = validAddress($('newsrv').value);
    if (!v) {
      message(box, 'err', 'Enter a valid hostname or IP, for example play.example.com.');
      return;
    }
    var list = getServers();
    if (list.indexOf(v) !== -1) { message(box, 'warn', v + ' is already saved.'); return; }
    if (list.length >= MAX_SAVED) { message(box, 'warn', 'You have hit the 20 server limit.'); return; }
    list.push(v);
    if (!setServers(list)) { message(box, 'err', 'This browser is blocking local storage, so nothing was saved.'); return; }
    $('newsrv').value = '';
    drawServers();
  }

  function drawServers() {
    var list = getServers();
    var ul = $('srvlist');
    clear(ul);

    if (!list.length) {
      ul.appendChild(el('li', 'empty', 'Nothing saved yet.'));
      return;
    }

    list.forEach(function (addr) {
      var li = el('li');
      li.appendChild(el('span', 'nm', addr));     // textContent, so no markup can escape

      var check = el('button', 'btn ghost', 'Check');
      check.addEventListener('click', function () {
        $('addr').value = addr;
        showTab('status');
        lookup();
      });

      var del = el('button', 'x', '×');
      del.setAttribute('aria-label', 'Remove ' + addr);
      del.addEventListener('click', function () {
        setServers(getServers().filter(function (x) { return x !== addr; }));
        drawServers();
      });

      li.appendChild(check);
      li.appendChild(del);
      ul.appendChild(li);
    });
  }

  /* ------------------------------------------------------------------ *
   * Tabs + wiring
   * ------------------------------------------------------------------ */
  var TABS = ['status', 'ram', 'saved'];
  function showTab(name) {
    if (TABS.indexOf(name) === -1) name = 'status';
    TABS.forEach(function (n) {
      $('p-' + n).className = (n === name) ? '' : 'hide';
      $('t-' + n).setAttribute('aria-selected', String(n === name));
    });
  }

  document.querySelectorAll('nav button[data-tab]').forEach(function (b) {
    b.addEventListener('click', function () { showTab(b.getAttribute('data-tab')); });
  });

  $('go').addEventListener('click', lookup);
  $('addr').addEventListener('keydown', function (e) { if (e.key === 'Enter') lookup(); });
  $('add').addEventListener('click', addServer);
  $('newsrv').addEventListener('keydown', function (e) { if (e.key === 'Enter') addServer(); });
  $('copy').addEventListener('click', copyFlags);

  ['stype', 'hostram', 'players', 'mods', 'vd'].forEach(function (id) {
    $(id).addEventListener('input', calc);
    $(id).addEventListener('change', calc);
  });

  calc();
  drawServers();
})();
