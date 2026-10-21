# emudhra-ca-check

Check whether the clients on your machine still trust the **eMudhra intermediate
CA certificates** whose private keys were compromised in October 2026.

Browsers and operating systems revoked the compromised intermediates quickly via
their revocation channels (OneCRL, CRLSets, etc.). But a lot of software doesn't
consume revocation information and keeps trusting those intermediates until its
**trust bundle** is updated — command-line `curl`, Node.js, Go, Python/`pip` +
`certifi`, custom CA bundles baked into projects, and Docker base images. Those
are exactly what this tool checks.

> **The logic is inverted.** This tool talks to two public probe hosts that serve
> a certificate chaining to a compromised intermediate. A **successful** HTTPS
> response means the client is **VULNERABLE** (it still trusts the bad chain). A
> **certificate-verification error** means the client is **safe**.

## Quick start

```sh
curl -fsSLO https://raw.githubusercontent.com/Fuxnet/emudhra-ca-check/main/emudhra-ca-check.sh
chmod +x emudhra-ca-check.sh
./emudhra-ca-check.sh
```

To also scan a projects folder for project-local CA bundles and risky lockfile
pins:

```sh
./emudhra-ca-check.sh ~/Projects
```

Exit codes: `0` all clear · `1` at least one client vulnerable · `2` no vulnerable
client found but some checks were inconclusive (usually no network egress to the
probe hosts).

## What it checks

- **curl** — every `curl` on `PATH`, using its own default trust store.
- **Node.js** — its compiled-in root store, via a live handshake. Reports version
  against the patched lines (`22.23.4` / `24.22.1` / `26.12.1`+).
- **Go** — its bundled roots, via a live handshake if `go` is installed
  (`1.27.3` / `1.26.10`+, CVE-2026-111943).
- **Python** — for each `python3` on `PATH`: the default `ssl` store, **pip's own
  vendored `certifi`** (the classic stale-on-macOS case), and top-level `certifi`
  if installed. Patched `certifi` is `2026.10.19`+.
- **Env & config overrides** — the sneakiest blind spot, because they silently
  redirect a client's trust to an arbitrary file. Checks `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`,
  `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE`,
  plus `~/.curlrc`, git `http.sslCAInfo`, `~/.npmrc`, `pip.conf` and `~/.wgetrc` —
  and live-tests whatever bundle each one points at.
- **Project bundles** (with a directory argument) — `*/certifi/cacert.pem`, custom
  `*.pem` / `ca-bundle*` files, and **venvs**, each live-tested. Plus a grep for a
  pinned old `certifi==` in `requirements*.txt` / `*.lock` that would silently
  reinstall a bad bundle on the next `pip install`.

Version numbers are only shown as a hint — the **live handshake is the source of
truth**, because a bundle can carry an old date yet still reject the chain, or a
recent-looking one can still trust it.

## Interpreting the results

**Trust the live verdict, not the version string.** The version numbers this tool
prints are only a hint — the handshake is the truth, and the two can disagree in
*both* directions:

- A bundle with an **old-looking version can still be safe.** On Debian/Ubuntu,
  `python3-certifi` is repackaged so that `certifi.where()` returns the system
  bundle (`/etc/ssl/certs/ca-certificates.crt`) rather than its own copy. So a
  "`certifi 2026.01.04`" there is really exercising your patched system
  `ca-certificates` and will correctly report **ok** — even though the upstream
  bundle of that version is not patched.
- A bundle with a **recent-looking version can still be vulnerable** — e.g. pip's
  self-contained *vendored* `certifi` carrying the compromised roots, independent
  of your system store.

The same `certifi 2026.01.04` can read **ok** in one place and **VULNERABLE** in
another for exactly this reason. That's not a false positive — they're different
files that happen to share a version number. Had you gone by version alone you'd
have "fixed" the safe one and missed the vulnerable one. Always act on the
`VULNERABLE` / `ok` verdict, and use the version only to pick the fix.

`inconclusive` means the client could not reach the probe hosts (usually no
egress) — it is never treated as safe. See below for the offline method.

## Offline / no-egress use

The tool sends handshakes to a third party's probe hosts
(`*.we-have-a-problem.com`). If you can't or don't want to reach them, the
disclosure site publishes **`chains.zip`** — the exact chains each probe host
serves, in PEM — so you can verify against your own trust store with no network
dependency. Checks that can't reach the hosts are reported as *inconclusive*,
never as a false *safe*.

## For Claude Code users

[`PROMPT.md`](./PROMPT.md) is a paste-ready prompt that does the same checks from
inside a Claude Code session and will additionally walk your project and fix
issues in place — reporting first, and asking before any change.

## Remediation

This tool **only reports** — it changes nothing. For per-client fixes (updating
bundles, the macOS `/etc/ssl/cert.pem` and `pip` workarounds, Linux
`ca-certificates` steps, etc.), see the official disclosure site:

**https://emudhra.we-have-a-problem.com/**

## Known gaps — PRs welcome

This tool deliberately favours being fast, portable and low-false-positive over
exhaustive coverage, so it checks the clients and bundles that carry the real
day-to-day risk and skips a few surfaces on purpose. If your environment includes
these, check them by hand — and contributions that add them (gracefully, with no
new hard dependencies) are very welcome:

- **Java `cacerts` keystores** — JKS/PKCS12, not PEM, so they need `keytool` and
  fingerprint matching rather than a `curl` handshake. Relevant for JVM services.
- **NSS databases** (`cert9.db`; Firefox and some Linux clients) — need
  `certutil`. Note that Firefox itself is protected via OneCRL regardless.
- **Snap / Flatpak runtimes (Linux)** — each bundles its own `ca-certificates`
  that goes stale independently of the host; not yet scanned.
- **Full-filesystem crawl** — the tool checks known locations and project trees,
  not every `.pem` on disk, to avoid flagging unrelated test fixtures.
- **macOS Keychain / OS trust APIs** — clients using these follow OS revocation
  and are already protected, so they're out of scope by design.

To match a store's certificates by fingerprint, the compromised roots' SHA-256
and SPKI hashes are published in the disclosure site's `roots.json`.

## Credit

The incident disclosure, the proof, and the probe hosts this tool relies on are
the work of **Dennis Jackson** and the reporters credited on the disclosure site
(<https://emudhra.we-have-a-problem.com/>, source at
<https://github.com/galadran/we-have-a-problem.com>). This repository is just a
convenience checker built on top of that work. If you've verified a package or
version that isn't listed in the disclosure site's affected-software table,
consider sending a PR there — it helps more people than a standalone script does.

## License

MIT — see [`LICENSE`](./LICENSE).
