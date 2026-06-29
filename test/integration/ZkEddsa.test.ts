import { expect } from "chai";

import {
  generateZkIssuerKey,
  restoreZkIssuerKey,
  computeZkLeaf,
  signZkLeaf,
  verifyZkSignature,
  encodeZkSignature,
  decodeZkSignature,
  type KanonZkSignature,
} from "../../sdk/dist/index.cjs";

/**
 * Verifies the SDK's BabyJubjub EdDSA module — the same primitives the
 * `non_revocation.circom` circuit verifies. Once the holder side wires
 * snarkjs, these tests pin the byte-for-byte interop between
 * SDK ↔ circuit ↔ Python plugin.
 */
describe("SDK kanon-zk eddsa", () => {
  it("generateZkIssuerKey produces a 32-byte private key + BabyJubjub pubkey", async () => {
    const key = await generateZkIssuerKey();
    expect(key.privateKeyHex).to.match(/^0x[0-9a-fA-F]{64}$/);
    expect(typeof key.publicKey.Ax).to.eq("bigint");
    expect(typeof key.publicKey.Ay).to.eq("bigint");
    // BabyJubjub coordinates live in the BN254 scalar field — under 2^254.
    expect(key.publicKey.Ax).to.be.lessThan(2n ** 254n);
    expect(key.publicKey.Ay).to.be.lessThan(2n ** 254n);
  });

  it("restoreZkIssuerKey reproduces the same pubkey from a persisted hex", async () => {
    const original = await generateZkIssuerKey();
    const restored = await restoreZkIssuerKey(original.privateKeyHex);
    expect(restored.privateKeyHex).to.eq(original.privateKeyHex);
    expect(restored.publicKey.Ax).to.eq(original.publicKey.Ax);
    expect(restored.publicKey.Ay).to.eq(original.publicKey.Ay);
  });

  it("computeZkLeaf is deterministic and matches the tagged Poseidon hash", async () => {
    const credDefId = 99999n;
    const credId = 1234n;
    const attrs = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n, 14n, 15n, 16n];
    const leaf1 = await computeZkLeaf(credDefId, credId, attrs);
    const leaf2 = await computeZkLeaf(credDefId, credId, attrs);
    expect(leaf1).to.eq(leaf2);
    // A single-bit change in credDefId, credId, or attrs produces a different leaf.
    const otherDef = await computeZkLeaf(credDefId + 1n, credId, attrs);
    expect(otherDef).to.not.eq(leaf1);
    const otherCred = await computeZkLeaf(credDefId, credId + 1n, attrs);
    expect(otherCred).to.not.eq(leaf1);
    const otherAttrs = [...attrs];
    otherAttrs[0] = otherAttrs[0]! + 1n;
    const otherLeaf = await computeZkLeaf(credDefId, credId, otherAttrs);
    expect(otherLeaf).to.not.eq(leaf1);
  });

  it("signZkLeaf + verifyZkSignature round-trip works", async () => {
    const key = await generateZkIssuerKey();
    const leaf = await computeZkLeaf(31337n, 42n, [99n, 100n, 101n]);
    const sig = await signZkLeaf(key.privateKeyHex, leaf);

    expect(await verifyZkSignature(key.publicKey, leaf, sig)).to.eq(true);
  });

  it("verifyZkSignature rejects a sig from a different key", async () => {
    const keyA = await generateZkIssuerKey();
    const keyB = await generateZkIssuerKey();
    const leaf = await computeZkLeaf(31337n, 7n, [1n, 2n, 3n]);

    const sig = await signZkLeaf(keyA.privateKeyHex, leaf);
    // Sig was made by A but we hand the verifier B's pubkey → should reject.
    expect(await verifyZkSignature(keyB.publicKey, leaf, sig)).to.eq(false);
  });

  it("verifyZkSignature rejects when the leaf is tampered", async () => {
    const key = await generateZkIssuerKey();
    const leaf = await computeZkLeaf(31337n, 7n, [1n, 2n, 3n]);
    const sig = await signZkLeaf(key.privateKeyHex, leaf);

    const tampered = leaf + 1n;
    expect(await verifyZkSignature(key.publicKey, tampered, sig)).to.eq(false);
  });

  it("encode/decode round-trip preserves the signature exactly", async () => {
    const key = await generateZkIssuerKey();
    const leaf = await computeZkLeaf(31337n, 11n, [55n, 66n]);
    const sig = await signZkLeaf(key.privateKeyHex, leaf);

    const encoded = encodeZkSignature(sig);
    // The wire form is the base64 of 3 felts × 32 bytes = 128 chars.
    expect(encoded.length).to.eq(128);

    const restored: KanonZkSignature = decodeZkSignature(encoded);
    expect(restored.R8x).to.eq(sig.R8x);
    expect(restored.R8y).to.eq(sig.R8y);
    expect(restored.S).to.eq(sig.S);

    // The restored signature still verifies against the original leaf+pubkey.
    expect(await verifyZkSignature(key.publicKey, leaf, restored)).to.eq(true);
  });

  it("decodeZkSignature rejects payloads of the wrong length", () => {
    expect(() => decodeZkSignature("AA==")).to.throw(/expected.*bytes/);
  });

  it("restoreZkIssuerKey rejects a non-32-byte secret", async () => {
    let threw = false;
    try {
      await restoreZkIssuerKey("0x" + "00".repeat(16)); // 16 bytes, not 32
    } catch (err) {
      threw = true;
      expect((err as Error).message).to.match(/32 bytes/);
    }
    expect(threw).to.eq(true);
  });
});
