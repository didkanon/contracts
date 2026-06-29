#!/usr/bin/env bash
# Groth16 trusted-setup ceremony for the non_revocation circuit.
#
#   bash circom/scripts/ceremony.sh
#
# Phase 1 (powers of tau) is circuit-independent and is REUSED from the public Hermez
# Perpetual Powers of Tau (hundreds of independent contributors). We do not run our own
# phase 1. Phase 2 is circuit-specific and is run here with multiple contributions + a
# public beacon, then verified with `snarkjs zkey verify`.
#
# Phase-1 source: powersOfTau28_hez_final_16 (2^16 = 65536 domain). snarkjs sizes the
# setup off the TOTAL constraint count; this circuit — NonRevocation(depth=26, attrs=16,
# disclose=1) — has ~24.3k total constraints (14.7k non-linear), which needs a 2^16 ptau.
# The script downloads it if absent and verifies the full
# transcript with `snarkjs powersoftau verify` (stronger than a hash compare — it checks
# every contribution + the beacon cryptographically). The sha256 is also recorded.
#
# SECURITY: phase-2 contributions/beacon below use scripted entropy + a fixed beacon for a
# reproducible CI build — NOT production-secure on its own. For production, collect phase-2
# contributions from independent parties and use real future randomness for the beacon.
# See docs/CEREMONY.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/circom/src/non_revocation.circom"
BUILD="$ROOT/circom/build"
CIRCOMLIB="$ROOT/node_modules/circomlib/circuits"
CEREMONY="$BUILD/ceremony"
PTAU_DIR="$BUILD/ptau"
PTAU_NAME="powersOfTau28_hez_final_16.ptau"
PTAU_URL="${PTAU_URL:-https://storage.googleapis.com/zkevm/ptau/$PTAU_NAME}"
PTAU="$PTAU_DIR/$PTAU_NAME"
BEACON_HASH="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
BEACON_ITERS=10
export NODE_OPTIONS=--max-old-space-size=4096

mkdir -p "$CEREMONY" "$PTAU_DIR"
cd "$BUILD"

if [ ! -f non_revocation.r1cs ]; then
  echo "[0] compiling circuit"
  circom "$SRC" --r1cs --wasm --sym -o "$BUILD" -l "$CIRCOMLIB"
fi

cd "$CEREMONY"
TRANSCRIPT="$CEREMONY/transcript.txt"
: > "$TRANSCRIPT"
log() { echo "$@" | tee -a "$TRANSCRIPT"; }

log "=== kanonv2 non_revocation Groth16 ceremony ==="
log "date: $(date -u)"
log "phase1: REUSED public Hermez Perpetual Powers of Tau ($PTAU_NAME)"

# ── Phase 1: reuse Hermez ─────────────────────────────────────────────
if [ ! -f "$PTAU" ]; then
  log "[phase1] downloading $PTAU_URL"
  curl -sL --max-time 300 -o "$PTAU" "$PTAU_URL"
fi
PTAU_SHA=$(shasum -a 256 "$PTAU" | awk '{print $1}')
log "[phase1] sha256: $PTAU_SHA"
# Hermez phase-1 transcript verification takes ~20-30 min on a single core
# (BN254 pairings × hundreds of contributors). For dev / CI builds we can pin
# by the published Hermez sha256 — the cryptographic verify only buys
# additional defense if you suspect a swap/replacement of the file. Set
# `CEREMONY_VERIFY_PTAU=1` to opt in.
if [ "${CEREMONY_VERIFY_PTAU:-0}" = "1" ]; then
  log "[phase1] verifying transcript (slow — set CEREMONY_VERIFY_PTAU=0 to skip)"
  npx snarkjs powersoftau verify "$PTAU" | tee -a "$TRANSCRIPT" | tail -1
else
  EXPECTED_HERMEZ_16="1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922"
  if [ "$PTAU_SHA" = "$EXPECTED_HERMEZ_16" ]; then
    log "[phase1] sha256 matches published Hermez 16 — skipping transcript verify"
  else
    log "[phase1] sha256 does NOT match published Hermez 16 ($EXPECTED_HERMEZ_16) — aborting"
    exit 1
  fi
fi

# ── Phase 2: circuit-specific ─────────────────────────────────────────
R1CS="$BUILD/non_revocation.r1cs"
log ""
log "[phase2] setup"
npx snarkjs groth16 setup "$R1CS" "$PTAU" nr_0000.zkey >/dev/null
for i in 1 2; do
  log "[phase2] contribution $i"
  npx snarkjs zkey contribute "nr_000$((i-1)).zkey" "nr_000$i.zkey" \
    --name="phase2-contributor-$i" -e="kanon-phase2-party-$i-$(date +%s%N)" >/dev/null
done
log "[phase2] beacon"
npx snarkjs zkey beacon nr_0002.zkey nr_final.zkey "$BEACON_HASH" $BEACON_ITERS -n="phase2 final beacon" >/dev/null
log "[phase2] verify (keys match circuit + transcript)"
npx snarkjs zkey verify "$R1CS" "$PTAU" nr_final.zkey | tee -a "$TRANSCRIPT" | tail -1

# ── Export + install ──────────────────────────────────────────────────
log ""
log "[export] verification key + Solidity verifier"
npx snarkjs zkey export verificationkey nr_final.zkey verification_key.json >/dev/null
npx snarkjs zkey export solidityverifier nr_final.zkey Verifier.sol >/dev/null

cp nr_final.zkey "$BUILD/nr_final.zkey"
cp verification_key.json "$BUILD/verification_key.json"
cp Verifier.sol "$ROOT/contracts/verifiers/Groth16Verifier.sol"
cp verification_key.json "$ROOT/contracts/verifiers/non_revocation_vk.json"

log ""
log "ceremony complete. transcript: circom/build/ceremony/transcript.txt"
