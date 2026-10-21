# Claude Code prompt

Paste the block below into a Claude Code session (ideally from inside the project
you want checked). It runs the same inverted-handshake check as the script across
curl, Node, Go, and Python, walks the current project, reports a table first, and
asks before changing anything.

---

```
Check whether anything on this machine — and in this project — still trusts the
eMudhra intermediate CAs whose private keys were compromised in October 2026.

BACKGROUND (don't web-search, just use this): eight eMudhra intermediate CA certs
had recoverable private keys. Browsers/OSes revoked them via CRL, but clients that
don't consume revocation (curl, Node, Go, Python/pip+certifi, custom CA bundles,
Docker base images) keep trusting them until their trust BUNDLE is updated. The
fix is to stop trusting two roots: "emSign ECC Root CA - G3" and "AAA Certificate
Services". Patched certifi is 2026.10.19+; Node 22.23.4/24.22.1/26.12.1+; Go
1.27.3/1.26.10+ (CVE-2026-111943).

HOW TO TEST (authoritative — the logic is INVERTED): two public probe hosts serve
certs chaining to a compromised intermediate:
    https://dv-g3b-emudhra.we-have-a-problem.com/       (via emSign root)
    https://dv-g3b-aaa-emudhra.we-have-a-problem.com/   (via AAA/Comodo cross-sign)
A SUCCESSFUL HTTPS response = VULNERABLE (the client still trusts the bad chain).
A certificate-verification ERROR = SAFE. A client is only clear if it rejects BOTH.
Test a specific CA bundle with:  curl -sf --cacert <bundle> https://<host>/
(exit 0 = vulnerable; exit 60 = safe). Do NOT trust version strings alone — a bundle
can carry an old date yet still reject the chain; the handshake is the proof. If this
environment has no network egress to those hosts, say so and fall back to: flag any
certifi < 2026.10.19, and grep custom .pem bundles for the two root names above.

DO THIS:
1. Detect and live-test every trust store you can reach:
   - curl: each `curl` on PATH, using its default store.
   - Node: `node -v`, and a live test via its built-in root store.
   - Go: `go version`, and a live test via its bundled roots if `go` is present.
   - Python: for each `python3` on PATH — the default ssl store, pip's vendored
     bundle (from pip._vendor import certifi), and top-level certifi if installed.
   - This project: find ./ for */certifi/cacert.pem and custom *.pem / ca-bundle*
     (skip node_modules) and live-test each bundle.
   - Project venvs (.venv/venv): each froze its own certifi at creation — test them.
2. Flag regressions-in-waiting: grep requirements*.txt, *.lock, Pipfile.lock for a
   pinned old `certifi==` that would reinstall a bad bundle on next install.
3. Flag Docker: any FROM python:/node:/alpine/debian base predating the fix needs a
   no-cache rebuild with updated ca-certificates (can't be live-tested until rebuilt).
4. REPORT a table first: each client/bundle, its version, and VULNERABLE / safe /
   inconclusive from the live test. Change nothing yet.
5. Then, only after I confirm each one, remediate: update the venv's certifi to
   2026.10.19+ (or recreate it from a patched system python); bump a pinned
   certifi==; remove the two named roots from a custom .pem; bump Node/Go; rebuild
   Docker bases. Re-run the live test after each fix to confirm it now ERRORS on both
   probe hosts. Never edit the system trust store or run sudo without asking me.
```

---

Notes:

- **The approval gate is deliberate.** Some fixes have side effects (editing a
  system trust store, bumping a lockfile that then needs re-resolving) you don't
  want an agent doing unattended, so it reports first and asks.
- **The `certifi==` pin check is the sleeper.** A project can test clean today and
  silently regress the next time CI runs `pip install` against a pinned-old
  `certifi`. The live handshake alone won't catch that — hence the separate grep.
