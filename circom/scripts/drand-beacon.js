// Fetch a FUTURE drand round and print its randomness (64-hex) on stdout.
// A future round is unpredictable at contribution time and publicly verifiable afterward —
// exactly what a Groth16 phase-2 final beacon needs.
//
//   node drand-beacon.js [baseUrl] [roundsAhead]
//
// Diagnostics go to stderr; only the randomness hex goes to stdout (so the caller can capture it).
const base = (process.argv[2] || "https://drand.cloudflare.com").replace(/\/$/, "");
const ahead = Math.max(1, parseInt(process.argv[3] || "2", 10));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.json();
}

(async () => {
  if (typeof fetch !== "function") throw new Error("global fetch unavailable — need Node 18+");
  const info = await getJSON(`${base}/info`);
  const period = info.period || 30;
  const latest = await getJSON(`${base}/public/latest`);
  const target = latest.round + ahead;
  process.stderr.write(`drand: chain period ${period}s, latest round ${latest.round}, target ${target}\n`);
  process.stderr.write(`drand: target round number ${target} (record this — it is the beacon provenance)\n`);

  await sleep(period * ahead * 1000 + 4000); // wait until the target round should exist
  for (let i = 0; i < 30; i++) {
    try {
      const b = await getJSON(`${base}/public/${target}`);
      if (b && b.randomness && /^[0-9a-f]{64}$/i.test(b.randomness)) {
        process.stderr.write(`drand: round ${target} randomness obtained\n`);
        process.stdout.write(b.randomness + "\n");
        return;
      }
    } catch (_) {
      /* not published yet — keep polling */
    }
    await sleep(3000);
  }
  throw new Error(`drand: round ${target} not available after polling`);
})().catch((e) => {
  process.stderr.write(String(e && e.message ? e.message : e) + "\n");
  process.exit(1);
});
