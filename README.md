# Blockwatch

A small toolkit for people who run their own Minecraft servers. No build step, no framework,
no accounts, no backend — three static files you can open or host anywhere.

**Live site:** https://dev-master1203.github.io/blockwatch/
*(live once GitHub Pages is enabled)*

## What it does

**Server status** — type any Java or Bedrock server address and get its live player count,
version, software and message of the day. The MOTD is re-rendered with its original Minecraft
colour codes. Data comes from the public [mcsrvstat.us](https://api.mcsrvstat.us) API.

**RAM & JVM flag planner** — pick your server software, expected players, mod/plugin count and
view distance, and it works out how much RAM to allocate and prints a complete start command
using [Aikar's G1GC flags](https://docs.papermc.io/paper/aikars-flags), the community standard
tuning for Minecraft servers. It warns you if the allocation would starve the host machine.

**My servers** — save the addresses you check often. Stored in your own browser only; nothing
is uploaded and there is no account.

## Running it locally

Any static file server works. From this folder:

```bash
python -m http.server 8000
```

then open <http://localhost:8000>. Opening `index.html` directly from disk mostly works, but
some browsers restrict `localStorage` on `file://` URLs, so the saved list may not persist.

## Files

| File | Purpose |
|---|---|
| `index.html` | Markup and the Content Security Policy |
| `styles.css` | All styling |
| `app.js` | All behaviour — status lookup, calculator, saved list |
| `SECURITY.md` | Full security review: findings, fixes, residual risk |
| `security-test.js` | Automated harness that re-proves the fixes |

CSS and JS live in separate files on purpose: it lets the page enforce a Content Security Policy
with `script-src 'self'` and no `'unsafe-inline'`, which an all-in-one HTML file cannot do.

## Security

The site renders data it does not control — JSON from a third-party API, and values out of
`localStorage` — so it was reviewed for injection before release. Nine issues were found and
fixed, including two confirmed-exploitable cross-site scripting bugs. The review, with evidence
and the fixes, is in [SECURITY.md](SECURITY.md). To re-run the tests:

```bash
npm install playwright && npx playwright install chromium
node security-test.js
```

## Credits

Built for a CYBER 110 assignment at BYU. Server data from
[mcsrvstat.us](https://api.mcsrvstat.us). Not affiliated with Mojang or Microsoft.
