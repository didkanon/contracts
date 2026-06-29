#!/usr/bin/env bash
# ============================================================================
# kanonv2 — ONE-SHOT production trusted setup + build.
#
# Run this on your deployment machine and it does EVERYTHING:
#   1. compiles the circuit (r1cs + wasm)
#   2. downloads + integrity-checks the public Hermez phase-1 ptau (2^16)
#   3. runs phase-2 with YOUR entropy (openssl, generated at runtime, then discarded)
#   4. seals it with a REAL public beacon (auto-fetched FUTURE drand round; or pass BEACON=<hex>)
#   5. exports + installs the on-chain Groth16 verifier + proving key
#   6. hardhat compile
#   7. runs the Tier-2 ZK test — proves a real proof verifies on-chain
#
# Usage:
#   bash circom/scripts/contribute-prod.sh
#   BEACON=<64-hex>   bash circom/scripts/contribute-prod.sh   # supply your own beacon instead of drand
#   VERIFY_PTAU=1     bash circom/scripts/contribute-prod.sh   # full cryptographic ptau verify (slow)
#   SKIP_TEST=1       bash circom/scripts/contribute-prod.sh   # skip step 7
#
# Your entropy is `openssl rand` generated at run time and is never written anywhere — the only
# persisted secret-derived output is the proving/verifying key. After this finishes the secret
# is gone, which is what makes the setup sound (one honest contributor who discards entropy).
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CIRCOM_DIR="$ROOT/circom"
SRC="$CIRCOM_DIR/src/non_revocation.circom"
BUILD="$CIRCOM_DIR/build"
CIRCOMLIB="$ROOT/node_modules/circomlib/circuits"
PTAU_DIR="$BUILD/ptau"
PTAU_NAME="powersOfTau28_hez_final_16.ptau"
PTAU="$PTAU_DIR/$PTAU_NAME"
PTAU_URL="${PTAU_URL:-https://storage.googleapis.com/zkevm/ptau/$PTAU_NAME}"
# Hermez published hash for powersOfTau28_hez_final_16.ptau. Confirm once against the official
# snarkjs/Hermez list; the script refuses to proceed on a mismatch.
PTAU_SHA256="${PTAU_SHA256:-1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922}"
DRAND_URL="${DRAND_URL:-https://drand.cloudflare.com}"
DRAND_AHEAD="${DRAND_AHEAD:-2}"
DEV_BEACON="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
PROD="$BUILD/prod"
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=6144}"

command -v circom  >/dev/null || { echo "ERROR: circom not on PATH — install circom 2.x"  >&2; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl required (entropy source)"        >&2; exit 1; }
command -v curl    >/dev/null || { echo "ERROR: curl required"                             >&2; exit 1; }

mkdir -p "$PTAU_DIR" "$PROD"
TRANSCRIPT="$PROD/transcript.txt"
: > "$TRANSCRIPT"
log() { echo "$@" | tee -a "$TRANSCRIPT"; }

log "=== kanonv2 production trusted setup + build ==="
log "date: $(date -u)"

# ── 1. compile ──────────────────────────────────────────────────────────
log "[1/7] compiling circuit"
CC="$(circom "$SRC" --r1cs --wasm --sym -o "$BUILD" -l "$CIRCOMLIB" 2>&1)"
echo "$CC" | grep -iE "constraints|wires|template instances" | tee -a "$TRANSCRIPT" || true
R1CS="$BUILD/non_revocation.r1cs"
[ -f "$R1CS" ] || { echo "ERROR: compile produced no r1cs"; echo "$CC" >&2; exit 1; }

# ── 2. phase-1 ptau (reused public Hermez ceremony) ─────────────────────
if [ ! -f "$PTAU" ]; then
  log "[2/7] downloading public phase-1 $PTAU_URL"
  curl -fL --max-time 600 -o "$PTAU" "$PTAU_URL"
else
  log "[2/7] phase-1 already present"
fi
GOT_SHA="$(shasum -a 256 "$PTAU" | awk '{print $1}')"
log "      sha256: $GOT_SHA"
if [ -n "$PTAU_SHA256" ] && [ "$GOT_SHA" != "$PTAU_SHA256" ]; then
  echo "ERROR: ptau sha256 mismatch — expected $PTAU_SHA256. Refusing to proceed." >&2
  exit 1
fi
if [ "${VERIFY_PTAU:-0}" = "1" ]; then
  log "      full cryptographic verify (slow)…"
  npx snarkjs powersoftau verify "$PTAU" | tee -a "$TRANSCRIPT" | tail -1
fi

# ── 3. beacon (real public randomness) ──────────────────────────────────
if [ -n "${BEACON:-}" ]; then
  if [ "$BEACON" = "$DEV_BEACON" ]; then
    echo "ERROR: BEACON is the dev placeholder. Use real public randomness or omit it to auto-fetch drand." >&2
    exit 1
  fi
  BEACON_SRC="user-supplied"
else
  log "[beacon] fetching a FUTURE drand round (+$DRAND_AHEAD) from $DRAND_URL (waits ~$((30 * DRAND_AHEAD))s)"
  BEACON="$(node "$CIRCOM_DIR/scripts/drand-beacon.js" "$DRAND_URL" "$DRAND_AHEAD" 2> >(tee -a "$TRANSCRIPT" >&2) | tail -1)"
  [ -n "$BEACON" ] || { echo "ERROR: drand beacon fetch failed (set BEACON=<hex> to supply your own)" >&2; exit 1; }
  BEACON_SRC="drand $DRAND_URL"
fi
log "[beacon] $BEACON  ($BEACON_SRC)"

# ── 4–5. phase-2 (the only part we run) ─────────────────────────────────
log "[3/7] phase-2 setup from Hermez ptau"
npx snarkjs groth16 setup "$R1CS" "$PTAU" "$PROD/nr_0000.zkey" >/dev/null
log "[4/7] your contribution (OS entropy, generated now and discarded)"
npx snarkjs zkey contribute "$PROD/nr_0000.zkey" "$PROD/nr_0001.zkey" \
  --name="$(whoami)@$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)" -e="$(openssl rand -hex 64)" >/dev/null
log "[5/7] final public beacon + verify"
npx snarkjs zkey beacon "$PROD/nr_0001.zkey" "$PROD/nr_final.zkey" "$BEACON" 10 -n="production beacon" >/dev/null
npx snarkjs zkey verify "$R1CS" "$PTAU" "$PROD/nr_final.zkey" | tee -a "$TRANSCRIPT" | tail -1

# ── export + install over the committed dev artifacts ───────────────────
npx snarkjs zkey export verificationkey "$PROD/nr_final.zkey" "$PROD/verification_key.json" >/dev/null
npx snarkjs zkey export solidityverifier "$PROD/nr_final.zkey" "$PROD/Verifier.sol" >/dev/null
cp "$PROD/nr_final.zkey"          "$BUILD/nr_final.zkey"
cp "$PROD/verification_key.json" "$BUILD/verification_key.json"
cp "$PROD/Verifier.sol"          "$ROOT/contracts/verifiers/Groth16Verifier.sol"
cp "$PROD/verification_key.json" "$ROOT/contracts/verifiers/non_revocation_vk.json"
rm -f "$PROD/nr_0000.zkey" "$PROD/nr_0001.zkey"

# ── 6. hardhat compile ──────────────────────────────────────────────────
log "[6/7] hardhat compile"
( cd "$ROOT" && npx hardhat compile ) >>"$TRANSCRIPT" 2>&1 \
  && log "      compiled OK" \
  || { echo "ERROR: hardhat compile failed — see $TRANSCRIPT" >&2; exit 1; }

# ── 7. on-chain proof test ──────────────────────────────────────────────
if [ "${SKIP_TEST:-0}" != "1" ]; then
  log "[7/7] Tier-2 ZK test (real proof verified on-chain)"
  ( cd "$ROOT" && npx hardhat test test/Tier2ZK.test.ts ) | tee -a "$TRANSCRIPT"
else
  log "[7/7] skipped (SKIP_TEST=1)"
fi

log ""
log "DONE — production proving key + verifier installed."
log "  proving key:  circom/build/nr_final.zkey"
log "  verifier:     contracts/verifiers/Groth16Verifier.sol"
log "  attestation:  $TRANSCRIPT  (ptau sha256, beacon provenance, verify results)"
log ""
log "Next: deploy Groth16Verifier + Groth16NonRevocationVerifier, register in the verifier"
log "registry, setZkVerifier on the affected credDefs, then publish the transcript."
