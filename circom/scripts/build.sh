#!/usr/bin/env bash
# Build the Tier-2 non-revocation circuit: compile, run a (dev) trusted setup, and
# export the Solidity verifier + verification key.
#
# Prereqs: circom 2.x, snarkjs (npm), circomlib (npm). Run from kanonv2/.
#
#   bash circom/scripts/build.sh
#
# PRODUCTION: replace the dev powers-of-tau + zkey contributions below with a real
# multi-party ceremony (e.g. reuse the Hermez perpetual powers-of-tau phase 1, then
# collect independent phase-2 contributions). The dev entropy here is NOT secure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/circom/src/non_revocation.circom"
BUILD="$ROOT/circom/build"
CIRCOMLIB="$ROOT/node_modules/circomlib/circuits"
export NODE_OPTIONS=--max-old-space-size=4096

mkdir -p "$BUILD"
cd "$BUILD"

echo "[1/5] compile circuit"
circom "$SRC" --r1cs --wasm --sym -o "$BUILD" -l "$CIRCOMLIB"

echo "[2/5] powers of tau (phase 1, dev)"
npx snarkjs powersoftau new bn128 14 pot14_0.ptau -v
npx snarkjs powersoftau contribute pot14_0.ptau pot14_1.ptau --name="dev" -e="kanon-dev-entropy-1"
npx snarkjs powersoftau prepare phase2 pot14_1.ptau pot14_final.ptau -v

echo "[3/5] groth16 setup (phase 2, dev)"
npx snarkjs groth16 setup non_revocation.r1cs pot14_final.ptau nr_0.zkey
npx snarkjs zkey contribute nr_0.zkey nr_final.zkey --name="dev2" -e="kanon-dev-entropy-2"

echo "[4/5] export verification key"
npx snarkjs zkey export verificationkey nr_final.zkey verification_key.json

echo "[5/5] export Solidity verifier -> contracts/verifiers/"
npx snarkjs zkey export solidityverifier nr_final.zkey Verifier.sol
cp Verifier.sol "$ROOT/contracts/verifiers/Groth16Verifier.sol"
cp verification_key.json "$ROOT/contracts/verifiers/non_revocation_vk.json"

echo "done. artifacts in circom/build; verifier copied to contracts/verifiers/Groth16Verifier.sol"
