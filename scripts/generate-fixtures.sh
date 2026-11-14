#!/usr/bin/env bash
# Regenerates the pre-generated test certificates under test/fixtures.
# Requires openssl >= 3.2 (for x509 -not_before/-not_after). The generated
# PEMs are committed, so running the tests does NOT require openssl.
set -euo pipefail

FIX="$(cd "$(dirname "$0")/../test/fixtures" && pwd)"
mkdir -p "$FIX"
cd "$FIX"

SERIAL=1000

rsa_key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null; }
ec_key()  { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" 2>/dev/null; }

selfsign() { # name subject extra-addext...
  local name="$1" subj="$2"; shift 2
  local args=(req -x509 -new -key "$name.key" -subj "$subj" -days 3650
    -set_serial $((SERIAL++)) -out "$name.crt"
    -addext "basicConstraints=critical,CA:TRUE"
    -addext "keyUsage=critical,keyCertSign,cRLSign"
    -addext "subjectKeyIdentifier=hash")
  for ext in "$@"; do args+=(-addext "$ext"); done
  openssl "${args[@]}" 2>/dev/null
}

sign() { # name subject ca-name extra-addext...
  local name="$1" subj="$2" ca="$3"; shift 3
  openssl req -new -key "$name.key" -subj "$subj" -out "$name.csr" 2>/dev/null
  local extfile
  extfile="$(mktemp)"
  for ext in "$@"; do echo "$ext" >> "$extfile"; done
  openssl x509 -req -in "$name.csr" -CA "$ca.crt" -CAkey "$ca.key" \
    -set_serial $((SERIAL++)) -days 3650 -out "$name.crt" \
    -extfile "$extfile" 2>/dev/null
  rm -f "$name.csr" "$extfile"
}

CA_EXT=("basicConstraints=critical,CA:TRUE" "keyUsage=critical,keyCertSign,cRLSign" "subjectKeyIdentifier=hash")
sign_ca() { # name subject ca-name extra...
  local name="$1" subj="$2" ca="$3"; shift 3
  sign "$name" "$subj" "$ca" "${CA_EXT[@]}" "$@"
}

LEAF_EXT=("basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment")
sign_leaf() { # name subject ca-name extra...
  local name="$1" subj="$2" ca="$3"; shift 3
  sign "$name" "$subj" "$ca" "${LEAF_EXT[@]}" "$@"
}

# --- main hierarchy ---------------------------------------------------------
rsa_key rootA;      selfsign rootA      "/CN=Root A"
ec_key  rootB;      selfsign rootB      "/CN=Root B"
rsa_key interA;     sign_ca  interA     "/CN=Inter A" rootA
# Cross-signed copy of interA: same key and subject, issued by rootB.
cp interA.key interA-cross.key
sign_ca interA-cross "/CN=Inter A" rootB
# Rogue intermediate: identical subject CN=Inter A but a different key.
rsa_key rogue-inter; sign_ca rogue-inter "/CN=Inter A" rootA

rsa_key leaf-good
sign_leaf leaf-good "/CN=www.good.example" interA \
  "subjectAltName=DNS:www.good.example" "extendedKeyUsage=critical,serverAuth"

rsa_key leaf-eku-bad
sign_leaf leaf-eku-bad "/CN=eku.bad.example" interA \
  "subjectAltName=DNS:eku.bad.example" "extendedKeyUsage=critical,clientAuth"

rsa_key leaf-wildcard
sign_leaf leaf-wildcard "/CN=wild.example" interA \
  "subjectAltName=DNS:*.wild.example" "extendedKeyUsage=serverAuth"

rsa_key leaf-cn-only
sign_leaf leaf-cn-only "/CN=cnonly.good.example" interA \
  "extendedKeyUsage=serverAuth"

rsa_key leaf-unknowncrit
sign_leaf leaf-unknowncrit "/CN=unknowncrit.example" interA \
  "subjectAltName=DNS:unknowncrit.example" "extendedKeyUsage=serverAuth" \
  "1.3.6.1.4.1.99999.1=critical,DER:05:00"

rsa_key leaf-revoked
sign_leaf leaf-revoked "/CN=revoked.good.example" interA \
  "subjectAltName=DNS:revoked.good.example" "extendedKeyUsage=serverAuth"

# Expired leaf (validity window entirely in the past).
rsa_key leaf-expired
openssl req -new -key leaf-expired.key -subj "/CN=expired.good.example" -out leaf-expired.csr 2>/dev/null
cat > leaf-expired.ext <<'EOF'
basicConstraints=critical,CA:FALSE
subjectAltName=DNS:expired.good.example
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in leaf-expired.csr -CA interA.crt -CAkey interA.key \
  -set_serial $((SERIAL++)) \
  -not_before 20190101000000Z -not_after 20200101000000Z \
  -out leaf-expired.crt \
  -extfile leaf-expired.ext 2>/dev/null
rm -f leaf-expired.csr leaf-expired.ext

# --- broken chain: issuer's anchor is never provided ------------------------
rsa_key interUnknown; selfsign interUnknown "/CN=Inter Unknown"
rsa_key leaf-broken
sign_leaf leaf-broken "/CN=broken.example" interUnknown \
  "subjectAltName=DNS:broken.example" "extendedKeyUsage=serverAuth"

# --- cross-signed cycle: caX <-> caY, rootC also signs caX -------------------
rsa_key rootC; selfsign rootC "/CN=Root C"
rsa_key caX; rsa_key caY
# Throwaway self-signed certs, only used so openssl picks up the right issuer
# name when cross-signing the pair. Not part of the fixtures.
cp caX.key caX-tmp.key; selfsign caX-tmp "/CN=CA X"
cp caY.key caY-tmp.key; selfsign caY-tmp "/CN=CA Y"
cp caX.key caX-by-caY.key;    sign_ca caX-by-caY    "/CN=CA X" caY-tmp
cp caX.key caX-by-rootC.key;  sign_ca caX-by-rootC  "/CN=CA X" rootC
cp caY.key caY-by-caX.key;    sign_ca caY-by-caX    "/CN=CA Y" caX-tmp
rsa_key leaf-cycle
sign_leaf leaf-cycle "/CN=cycle.example" caY-by-caX \
  "subjectAltName=DNS:cycle.example" "extendedKeyUsage=serverAuth"
rm -f caX-tmp.key caX-tmp.crt caY-tmp.key caY-tmp.crt

# --- name constraints --------------------------------------------------------
rsa_key rootNC
selfsign rootNC "/CN=Root NC" "nameConstraints=critical,permitted;DNS:allowed.example"
rsa_key interNC; sign_ca interNC "/CN=Inter NC" rootNC
rsa_key leaf-nc-denied
sign_leaf leaf-nc-denied "/CN=www.denied.example" interNC \
  "subjectAltName=DNS:www.denied.example" "extendedKeyUsage=serverAuth"
rsa_key leaf-nc-ok
sign_leaf leaf-nc-ok "/CN=www.allowed.example" interNC \
  "subjectAltName=DNS:www.allowed.example" "extendedKeyUsage=serverAuth"

# --- path length constraint --------------------------------------------------
rsa_key rootPL; selfsign rootPL "/CN=Root PL"
rsa_key interPL; sign_ca interPL "/CN=Inter PL" rootPL "basicConstraints=critical,CA:TRUE,pathlen:0"
rsa_key subPL;   sign_ca subPL   "/CN=Sub PL"   interPL
rsa_key leafPL
sign_leaf leafPL "/CN=pathlen.example" subPL \
  "subjectAltName=DNS:pathlen.example" "extendedKeyUsage=serverAuth"

rm -f ./*.csr
echo "fixtures generated in $FIX"
