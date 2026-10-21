#!/usr/bin/env bash
#
# emudhra-ca-check.sh
# Check whether local clients still trust the compromised eMudhra intermediate
# CAs (October 2026 incident). Reports only -- makes NO changes to your system.
#
# METHOD: a live TLS handshake against the two public probe hosts from the
# disclosure site https://emudhra.we-have-a-problem.com/ (by Dennis Jackson).
# The logic is INVERTED:
#     successful HTTPS response  -> client is VULNERABLE (still trusts bad chain)
#     certificate verify error   -> client is SAFE (rejects the compromised chain)
# Both probe hosts serve a cert chaining to the compromised "EM DV TLS CA - G3B"
# intermediate: "-emudhra" via the emSign ECC Root CA - G3, "-aaa-emudhra" via
# the AAA Certificate Services (Comodo) cross-sign. A client is only clear if it
# rejects BOTH.
#
# Version numbers are NOT trusted as proof -- a bundle can carry an old date yet
# still reject the chain, or vice versa. The handshake is authoritative.
#
# Note: this sends traffic to a third party's test hosts. For a fully offline
# check, use chains.zip from the disclosure site and verify against your store.
#
# Usage:   ./emudhra-ca-check.sh [PROJECTS_DIR]
#   PROJECTS_DIR (optional): recurse it for project-local certifi bundles and
#   custom *.pem CA files, and live-test each.
#
# Exit code: 0 if nothing vulnerable/inconclusive, 1 if any VULNERABLE found,
#   2 if some checks were inconclusive (e.g. no network egress) but none vulnerable.
#
# No warranty. MIT. Credit: disclosure + probe hosts by Dennis Jackson.

set -u

DOMAIN="we-have-a-problem.com"
HOSTS="dv-g3b-emudhra dv-g3b-aaa-emudhra"
EXPECTED_BODY="hello"   # probe hosts return "<h1>hello</h1>"; guards against captive portals / intercepting proxies
SCAN_DIR="${1:-}"
TIMEOUT=8

any_vuln=0
any_inc=0

if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
  R=; G=; Y=; B=; N=
fi

have() { command -v "$1" >/dev/null 2>&1; }

# Dedupe a "which -a" list down to unique real paths.
uniq_bins() {
  local name p rp seen=""
  for p in $(command -v -a "$1" 2>/dev/null || which -a "$1" 2>/dev/null); do
    rp=$(readlink -f "$p" 2>/dev/null || echo "$p")
    case " $seen " in *" $rp "*) ;; *) seen="$seen $rp"; echo "$p";; esac
  done
}

verdict_line() {  # $1=label  $2=VULNERABLE|SAFE|INCONCLUSIVE|SKIP  $3=detail
  local label="$1" v="$2" detail="${3:-}"
  case "$v" in
    VULNERABLE)   any_vuln=1; printf "  ${R}${B}VULNERABLE${N}  %-34s %s\n" "$label" "$detail" ;;
    SAFE)         printf "  ${G}ok        ${N} %-34s %s\n" "$label" "$detail" ;;
    INCONCLUSIVE) any_inc=1;  printf "  ${Y}inconcl.  ${N} %-34s %s\n" "$label" "$detail" ;;
    SKIP)         printf "  --        %-34s %s\n" "$label" "$detail" ;;
  esac
}

# Live-test a curl trust decision.
# $1 = curl binary to use; $2 = optional --cacert path ("" = that curl's default store).
# Prints VULNERABLE if either host verifies, SAFE if both reject, else INCONCLUSIVE.
probe_curl() {
  local bin="$1" cacert="$2" h code body vuln=0 inc=0
  for h in $HOSTS; do
    if [ -n "$cacert" ]; then
      body=$("$bin" -s --max-time "$TIMEOUT" --cacert "$cacert" "https://$h.$DOMAIN/" 2>/dev/null)
    else
      body=$("$bin" -s --max-time "$TIMEOUT" "https://$h.$DOMAIN/" 2>/dev/null)
    fi
    code=$?
    case "$code" in
      0)                     # handshake succeeded; confirm we actually reached the probe host
        case "$body" in
          *"$EXPECTED_BODY"*) vuln=1 ;;   # genuine probe response -> trusts the bad chain
          *)                  inc=1 ;;    # 200 from a captive portal / intercepting proxy -> can't trust this
        esac ;;
      60|51) : ;;            # 60 = cert verify failed, 51 = mismatch -> rejected (safe)
      *)     inc=1 ;;        # 6 dns / 7 connect / 28 timeout / etc -> no egress?
    esac
  done
  if [ "$vuln" = 1 ]; then echo VULNERABLE
  elif [ "$inc" = 1 ]; then echo INCONCLUSIVE
  else echo SAFE; fi
}

# Same, but for an OpenSSL-style hashed cert directory (--capath).
probe_capath() {
  local bin="$1" dir="$2" h code body vuln=0 inc=0
  for h in $HOSTS; do
    body=$("$bin" -s --max-time "$TIMEOUT" --capath "$dir" "https://$h.$DOMAIN/" 2>/dev/null)
    code=$?
    case "$code" in
      0) case "$body" in *"$EXPECTED_BODY"*) vuln=1 ;; *) inc=1 ;; esac ;;
      60|51) : ;;
      *) inc=1 ;;
    esac
  done
  if [ "$vuln" = 1 ]; then echo VULNERABLE
  elif [ "$inc" = 1 ]; then echo INCONCLUSIVE
  else echo SAFE; fi
}

CURLBIN="$(command -v curl 2>/dev/null || echo curl)"

# Test a CA path declared by an env var or config file: file -> --cacert, dir -> --capath.
FOUND_OVERRIDE=0
check_ca_path() {  # $1 = label, $2 = path, $3 = optional note
  local label="$1" p="$2" note="${3:-}"
  [ -z "$p" ] && return
  case "$p" in "~"*) p="$HOME${p#\~}" ;; esac   # expand leading ~
  FOUND_OVERRIDE=1
  if   [ -f "$p" ]; then verdict_line "$label" "$(probe_curl "$CURLBIN" "$p")" "$note"
  elif [ -d "$p" ]; then verdict_line "$label" "$(probe_capath "$CURLBIN" "$p")" "${note:-cert dir}"
  else                   verdict_line "$label" INCONCLUSIVE "path not found: $p"
  fi
}

echo "${B}eMudhra intermediate-CA trust check${N}  ($(date))"
echo "success = VULNERABLE, cert error = safe. Reports only; changes nothing."
echo

# ---- curl (every curl on PATH, using its own default store) ----
echo "${B}curl${N}"
if have curl; then
  for c in $(uniq_bins curl); do
    verdict_line "$c" "$(probe_curl "$c" "")" "$("$c" --version 2>/dev/null | head -1)"
  done
else
  verdict_line "curl" SKIP "not found"
fi
echo

# ---- Node.js (compiled-in root store) ----
echo "${B}Node.js${N}"
if have node; then
  nv=$(node -e 'const h=require("https"),d=process.argv[1],hs=["dv-g3b-emudhra","dv-g3b-aaa-emudhra"];let p=hs.length,vuln=false,inc=false;hs.forEach(x=>{const req=h.get({host:x+"."+d,timeout:8000},r=>{vuln=true;r.destroy();fin();});req.on("timeout",()=>req.destroy());req.on("error",e=>{if(!/CERT|ISSUER|SELF_SIGNED|VERIFY/.test(e.code||""))inc=true;fin();});});function fin(){if(--p===0)console.log(vuln?"VULNERABLE":inc?"INCONCLUSIVE":"SAFE");}' "$DOMAIN" 2>/dev/null)
  verdict_line "node $(node -v 2>/dev/null)" "${nv:-INCONCLUSIVE}" "patched: 22.23.4 / 24.22.1 / 26.12.1+"
else
  verdict_line "node" SKIP "not found"
fi
echo

# ---- Python: ssl store + pip-vendored + top-level certifi, per interpreter ----
echo "${B}Python${N}"
if have python3; then
  for py in $(uniq_bins python3); do
    pv=$("$py" -c 'import sys;print(sys.version.split()[0])' 2>/dev/null)
    # default ssl store
    sv=$("$py" - "$DOMAIN" <<'PY' 2>/dev/null
import sys,ssl,socket
d=sys.argv[1];vuln=False;inc=False
for h in ("dv-g3b-emudhra","dv-g3b-aaa-emudhra"):
    host=h+"."+d
    try:
        with socket.create_connection((host,443),8) as s, ssl.create_default_context().wrap_socket(s,server_hostname=host):
            vuln=True
    except ssl.SSLCertVerificationError: pass
    except Exception: inc=True
print("VULNERABLE" if vuln else "INCONCLUSIVE" if inc else "SAFE")
PY
)
    verdict_line "python $pv (ssl store)" "${sv:-INCONCLUSIVE}" "$py"
    # pip's own vendored bundle (the classic macOS stale case)
    pb=$("$py" -c 'from pip._vendor import certifi;print(certifi.where())' 2>/dev/null)
    if [ -n "$pb" ] && [ -f "$pb" ]; then
      pver=$("$py" -c 'from pip._vendor import certifi;print(certifi.__version__)' 2>/dev/null)
      verdict_line "python $pv (pip vendored)" "$(probe_curl "$CURLBIN" "$pb")" "certifi $pver"
    fi
    # top-level certifi, if installed
    cb=$("$py" -c 'import certifi;print(certifi.where())' 2>/dev/null)
    if [ -n "$cb" ] && [ -f "$cb" ]; then
      cver=$("$py" -c 'import certifi;print(certifi.__version__)' 2>/dev/null)
      verdict_line "python $pv (certifi)" "$(probe_curl "$CURLBIN" "$cb")" "certifi $cver (want 2026.10.19+)"
    fi
  done
else
  verdict_line "python3" SKIP "not found"
fi
echo

# ---- Go (uses its own bundled roots; patched 1.27.3 / 1.26.10+, CVE-2026-111943) ----
echo "${B}Go${N}"
if have go; then
  tmp=$(mktemp -d)
  cat > "$tmp/c.go" <<'GO'
package main
import ("fmt";"net/http";"time";"strings")
func main(){
  hs:=[]string{"dv-g3b-emudhra","dv-g3b-aaa-emudhra"}
  c:=&http.Client{Timeout:8*time.Second}
  vuln,inc:=false,false
  for _,h:=range hs{
    r,err:=c.Get("https://"+h+".we-have-a-problem.com/")
    if err==nil{vuln=true;r.Body.Close();continue}
    if strings.Contains(err.Error(),"certificate"){continue}
    inc=true
  }
  if vuln{fmt.Print("VULNERABLE")}else if inc{fmt.Print("INCONCLUSIVE")}else{fmt.Print("SAFE")}
}
GO
  gv=$(cd "$tmp" && go run c.go 2>/dev/null)
  verdict_line "go $(go version 2>/dev/null | awk '{print $3}')" "${gv:-INCONCLUSIVE}" "patched: go1.27.3 / go1.26.10+"
  rm -rf "$tmp"
else
  verdict_line "go" SKIP "not found"
fi
echo

# ---- Environment & config CA overrides (silently redirect a client's trust) ----
echo "${B}CA overrides (env & config)${N}"
# Env vars that point a client at a specific bundle FILE (or dir, for SSL_CERT_DIR).
for v in SSL_CERT_FILE CURL_CA_BUNDLE REQUESTS_CA_BUNDLE PIP_CERT \
         GIT_SSL_CAINFO CARGO_HTTP_CAINFO AWS_CA_BUNDLE NODE_EXTRA_CA_CERTS; do
  p="${!v:-}"
  [ -z "$p" ] && continue
  note=""; [ "$v" = "NODE_EXTRA_CA_CERTS" ] && note="(adds to Node's store)"
  check_ca_path "\$$v -> $p" "$p" "$note"
done
[ -n "${SSL_CERT_DIR:-}" ] && check_ca_path "\$SSL_CERT_DIR -> $SSL_CERT_DIR" "$SSL_CERT_DIR" "cert dir"

# Config files that declare a CA path.
if [ -f "$HOME/.curlrc" ]; then
  cp=$(sed -n 's/^[[:space:]]*-*cacert[[:space:]=]*//p' "$HOME/.curlrc" | tr -d '"' | head -1)
  check_ca_path "~/.curlrc cacert -> $cp" "$cp"
fi
if have git; then
  gi=$(git config --get http.sslCAInfo 2>/dev/null); check_ca_path "git http.sslCAInfo -> $gi" "$gi"
  gp=$(git config --get http.sslCAPath 2>/dev/null); check_ca_path "git http.sslCAPath -> $gp" "$gp"
fi
if [ -f "$HOME/.npmrc" ]; then
  cf=$(sed -n 's/^[[:space:]]*cafile[[:space:]]*=[[:space:]]*//p' "$HOME/.npmrc" | tr -d '"' | head -1)
  check_ca_path "~/.npmrc cafile -> $cf" "$cf"
fi
for f in "$HOME/.config/pip/pip.conf" "$HOME/.pip/pip.conf" /etc/pip.conf; do
  [ -f "$f" ] || continue
  pc=$(sed -n 's/^[[:space:]]*cert[[:space:]]*=[[:space:]]*//p' "$f" | tr -d '"' | head -1)
  check_ca_path "$f cert -> $pc" "$pc"
done
if [ -f "$HOME/.wgetrc" ]; then
  wc=$(sed -n 's/^[[:space:]]*ca_certificate[[:space:]]*=[[:space:]]*//p' "$HOME/.wgetrc" | tr -d '"' | head -1)
  check_ca_path "~/.wgetrc ca_certificate -> $wc" "$wc"
fi
[ "$FOUND_OVERRIDE" = 0 ] && verdict_line "none set" SAFE "clients use their default stores"
echo

# ---- Optional: project-local bundles ----
if [ -n "$SCAN_DIR" ]; then
  echo "${B}Project bundles under $SCAN_DIR${N}"
  if ! have curl; then
    verdict_line "scan" SKIP "curl required for bundle tests"
  else
    found=0
    while IFS= read -r b; do
      found=1
      verdict_line "$(echo "$b" | sed "s|$SCAN_DIR/||")" "$(probe_curl "$CURLBIN" "$b")" ""
    done < <(find "$SCAN_DIR" -type f \
               \( -path '*/certifi/cacert.pem' -o -name '*cacert*.pem' -o -name 'ca-bundle*.pem' \) \
               ! -path '*/node_modules/*' 2>/dev/null)
    # flag lockfile pins that would REINTRODUCE a bad bundle on next install
    pins=$(grep -rIl -E 'certifi==20(1[0-9]|2[0-5])' "$SCAN_DIR" \
             --include='requirements*.txt' --include='*.lock' --include='Pipfile.lock' 2>/dev/null)
    [ -n "$pins" ] && { echo; echo "  ${Y}pinned old certifi (will regress on install):${N}"; echo "$pins" | sed 's/^/    /'; }
    [ "$found" = 0 ] && [ -z "$pins" ] && verdict_line "scan" SAFE "no project bundles or old pins found"
  fi
  echo
fi

# ---- Summary ----
if [ "$any_vuln" = 1 ]; then
  echo "${R}${B}RESULT: at least one client still trusts the compromised intermediates.${N}"
  echo "See https://emudhra.we-have-a-problem.com/ for per-client remediation."
  exit 1
elif [ "$any_inc" = 1 ]; then
  echo "${Y}${B}RESULT: no vulnerable client found, but some checks were inconclusive${N}"
  echo "(often no network egress to the probe hosts). Re-run where egress is allowed,"
  echo "or verify offline with chains.zip from the disclosure site."
  exit 2
else
  echo "${G}${B}RESULT: all detected clients reject the compromised intermediates.${N}"
  exit 0
fi
