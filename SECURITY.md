# Security review — Blockwatch

**Reviewed:** November 2026
**Scope:** the whole site (`index.html`, `styles.css`, `app.js`) as deployed to GitHub Pages
**Method:** manual code review, plus an automated browser harness (`security-test.js`) that
loads the real page in headless Chromium and feeds it a **hostile API response** to confirm
whether each suspected flaw actually fires.

The key point about this app's threat model: it is a static site with no backend, no accounts
and no secrets, so the usual server-side bug classes (SQL injection, broken auth, IDOR) do not
apply. What *does* apply is that the page renders **data it does not control** — JSON from the
third-party `mcsrvstat.us` API, and values out of `localStorage`. Both are attacker-reachable:
the API could be compromised, spoofed by someone on a hostile network, or simply return a
server whose owner put HTML in their MOTD on purpose.

---

## Findings

| # | Severity | Issue | Status |
|---|----------|-------|--------|
| 1 | High | DOM XSS — third-party API data rendered via `innerHTML` | Fixed |
| 2 | High | Stored XSS — saved server names injected into an inline `onclick` attribute | Fixed |
| 3 | Medium | Path injection — user input concatenated into the API URL unvalidated | Fixed |
| 4 | Medium | No Content Security Policy | Fixed |
| 5 | Medium | Unvalidated `data:` URI used as an image source | Fixed |
| 6 | Low | `target="_blank"` without `rel="noopener"` (reverse tabnabbing) | Fixed |
| 7 | Low | Unhandled `JSON.parse` of `localStorage` crashes the page | Fixed |
| 8 | Low | No request timeout or rate limit on the third-party API | Fixed |
| 9 | Info | Referrer leakage to the API | Fixed |

---

### 1. DOM XSS via third-party API data — High

The first version took the API's convenience field `motd.html` — **pre-built HTML written by
whoever runs the queried server** — and dropped it straight into the page. Player names and the
version string went the same way.

```js
// before
h += '<div class="motd">' + d.motd.html.join('<br>') + '</div>';
h += 'Online: ' + d.players.list.map(p => p.name).join(', ');
out.innerHTML = h;
```

**Confirmed exploitable.** With the API mocked to return
`<span style="color:#55FF55">Welcome</span><img src=x onerror="window.__XSS_MOTD=1">`,
the harness reported `xss_motd: true`, `xss_player: true`, `xss_version: true` — the injected
script ran. In a real attack that script runs on the site's own origin and can read and rewrite
anything on the page, including the saved server list.

**Fix.** `app.js` contains no `innerHTML` at all. Every node is built with `createElement` and
filled with `textContent`, so markup in API data is displayed as literal text instead of being
parsed. `motd.html` is now ignored entirely; the MOTD is re-rendered from `motd.raw` by parsing
the Minecraft `§` colour codes ourselves and applying colours from a fixed 16-entry lookup
table. Colours and bold still work — the feature was hardened, not removed.

Re-test: `xss_motd: false`, `xss_player: false`, `xss_version: false`, `motd_coloured: true`.

### 2. Stored XSS via the saved server list — High

Saved addresses were written into a generated inline handler:

```js
// before
'<button onclick="checkSaved(\'' + a[i] + '\')">Check</button>'
```

A saved name of `x'),window.__XSS_SAVED=1,('` closes the string and the call, and the rest
executes as code. The payload persists in `localStorage`, so it re-fires on every page load.
Harness before the fix: `xss_saved_list: true`.

**Fix.** Three independent layers:
- There are no inline handlers anywhere; buttons get `addEventListener` with the address
  captured in a closure, so the value is never parsed as JavaScript.
- Names are written with `textContent`.
- Every entry is re-validated against the hostname grammar on read, so a payload like the one
  above is discarded before it reaches the DOM.

### 3. Path injection into the API URL — Medium

The address box was concatenated into the request path with no validation:

```js
var url = 'https://api.mcsrvstat.us/3/' + addr;   // before
```

Entering `a b/../../admin?x=1#frag` produced a request to
**`https://api.mcsrvstat.us/admin?x=1`** — the input escaped the intended `/3/` endpoint
entirely. On this API the blast radius is small, but the same bug against an API that has
privileged endpoints is a real server-side request forgery primitive, and it is the kind of
thing that gets much worse if a backend is ever added.

**Fix.** `validAddress()` enforces a strict grammar before any request is made — RFC-style
DNS labels or a dotted-quad IPv4, an optional `:port` in 1–65535, length caps — and the result
is then `encodeURIComponent`'d as defence in depth. Invalid input produces an error message and
**no network request at all**. Re-test: `raw_url: null`, `input_validated: true`.

### 4. No Content Security Policy — Medium

Nothing constrained what the page could load or where it could send data, so any injection
found later would have had a free hand.

**Fix.** CSS and JavaScript were moved out of `index.html` into `styles.css` and `app.js`
specifically so the policy could drop `'unsafe-inline'`, which is what makes a CSP actually
worth having:

```
default-src 'none'; base-uri 'none'; form-action 'none';
img-src 'self' data:; style-src 'self'; script-src 'self';
connect-src https://api.mcsrvstat.us;
```

`default-src 'none'` denies by default. `script-src 'self'` with no `'unsafe-inline'` means an
injected `<script>` or `onerror=` would not execute even if finding 1 came back.
`connect-src` pins outbound requests to the one API, so injected code could not exfiltrate to
an attacker's server. The page loads with **zero CSP violations**, confirming nothing in the
app depends on what the policy forbids.

### 5. Unvalidated `data:` URI as an image source — Medium

`d.icon` was assigned to `img.src` unchecked. The harness fed back
`data:text/html;base64,...` and the page accepted it (`icon_src: "data:text/html;base64,PH"`).
A `data:` URI from an untrusted source is a script-execution sink in the general case.

**Fix.** `safeIcon()` accepts only strings matching `^data:image/png;base64,[A-Za-z0-9+/]+={0,2}$`
and under 256 KB; anything else is dropped and no image is shown. The `alt` attribute is set to
`""` rather than to API-supplied text, since attribute values are another injection surface.
Re-test: `icon_src: null` — the hostile URI was rejected.

### 6. Reverse tabnabbing — Low

The footer link used `target="_blank"` with no `rel`, giving the opened page a `window.opener`
handle that can navigate the original tab to a phishing page. **Fix:** `rel="noopener noreferrer"`.
Re-test: `unsafe_target_blank: []`.

### 7. Corrupt `localStorage` breaks the page — Low

`JSON.parse(localStorage.getItem(...))` was unguarded, so a non-JSON value threw an uncaught
exception during init and the page stopped rendering — a persistent client-side denial of
service that a user could trigger on themselves and never recover from without clearing site
data. **Fix:** every storage read and write is wrapped in `try/catch` (which also covers private
mode and disabled storage), a parse failure falls back to an empty list, and the result must be
an array whose entries individually pass validation. Capped at 20 entries and de-duplicated.
Re-test: `breaks_on_bad_storage: false`, `storage_recovered: true`.

### 8. No timeout or rate limit — Low

A hung request left the button disabled forever, and holding Enter would hammer a free
third-party API. **Fix:** `AbortController` with a 12-second timeout, a 1.5-second minimum gap
between lookups, and non-2xx responses surfaced as a readable error instead of a raw exception.

### 9. Referrer leakage — Info

**Fix:** `<meta name="referrer" content="no-referrer">` plus `referrerPolicy: 'no-referrer'` on
the fetch, so the API is not told which page is calling it.

---

## Residual risk and accepted limitations

These are not fixed, and the reason is worth stating plainly rather than claiming the site is
"fully secure":

- **Clickjacking is not fully mitigated.** `frame-ancestors` and `X-Frame-Options` only work as
  HTTP *response headers*, and GitHub Pages does not let you set custom headers. It is
  deliberately omitted from the `<meta>` CSP because browsers ignore it there and only emit a
  console warning. Impact is low: the page has no state-changing action worth hijacking a click
  for. A host that supports custom headers (Netlify, Cloudflare Pages) would close this.
- **Third-party trust.** The site still depends on `mcsrvstat.us` for availability and honesty.
  The fixes above mean a malicious response can no longer execute code or exfiltrate data — the
  worst it can do now is display wrong numbers. Availability is handled gracefully with an error
  message rather than a broken page.
- **`localStorage` is not a secret store.** Saved addresses are readable by any script on this
  origin and by anyone with the device. That is acceptable because the data is a list of public
  server addresses, and the page stores nothing else.
- **No Subresource Integrity hashes**, because there are deliberately no third-party scripts or
  stylesheets to hash. Avoiding the dependency is the stronger control.
- **HTTPS** is enforced by GitHub Pages' "Enforce HTTPS" setting, which should be left on.

## Re-running the tests

```bash
npm install playwright && npx playwright install chromium
node security-test.js
```

The harness serves the site locally, intercepts the API with a hostile payload, and prints a
JSON result. A clean run reports every `xss_*` as `false`, `csp: true`, `csp_violations: []`,
`raw_url: null`, and `calc_ok`/`motd_coloured` as `true` — proving the fixes hold *and* that
they did not break the features.
