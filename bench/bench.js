// Stretch S4: load benchmark. Handout target: > 1,500 reads/sec with p99 < 15 ms.
//
//   node bench.js [--url http://localhost:3000] [--duration 15] [--connections 10,50] [--burns 3000]
//
// Scenarios:
//   view   GET /view/{id} on one long-lived secret: the read path (never changes state)
//   health GET /health: framework + DB round-trip baseline
//   create POST /api/secret
//   burn   POST /api/secret/{id}/burn, each pre-created 1-view secret burned exactly once
const autocannon = require("autocannon");

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const BASE = (args.url || "http://localhost:3000").replace(/\/$/, "");
const DURATION = Number(args.duration || 15);
const CONNECTIONS = (args.connections || "10,50").split(",").map(Number);
const BURNS = Number(args.burns || 3000);
const TARGET_RPS = 1500;
const TARGET_P99_MS = 15;

const run = (opts) => new Promise((resolve, reject) => {
  autocannon({ timeout: 10, ...opts }, (err, res) => (err ? reject(err) : resolve(res)));
});

async function createSecret(body) {
  const r = await fetch(`${BASE}/api/secret`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (r.status !== 201) throw new Error(`create failed: ${r.status} ${await r.text()}`);
  return (await r.json()).id;
}

function row(name, c, res) {
  return {
    scenario: name,
    connections: c,
    "req/s": Math.round(res.requests.average),
    "p50 ms": res.latency.p50,
    "p99 ms": res.latency.p99,
    "max ms": res.latency.max,
    requests: res.requests.total,
    "non-2xx": res.non2xx,
    errors: res.errors + res.timeouts,
  };
}

(async () => {
  const health = await fetch(`${BASE}/health`).catch(() => null);
  if (!health || health.status !== 200) throw new Error(`server not reachable at ${BASE}`);

  const viewId = await createSecret({ secret: "benchmark-read-target", ttl_seconds: 3600, max_views: 100 });
  const rows = [];

  console.log(`warm-up (3 s) ...`);
  await run({ url: `${BASE}/view/${viewId}`, connections: 10, duration: 3 });

  for (const c of CONNECTIONS) {
    console.log(`view   c=${c} ${DURATION}s ...`);
    rows.push(row("view (read)", c, await run({ url: `${BASE}/view/${viewId}`, connections: c, duration: DURATION })));
    console.log(`health c=${c} ${DURATION}s ...`);
    rows.push(row("health", c, await run({ url: `${BASE}/health`, connections: c, duration: DURATION })));
  }

  const c0 = CONNECTIONS[0];
  console.log(`create c=${c0} ${DURATION}s ...`);
  rows.push(row("create", c0, await run({
    url: `${BASE}/api/secret`, method: "POST", connections: c0, duration: DURATION,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secret: "benchmark-create", ttl_seconds: 60, max_views: 1 }),
  })));

  console.log(`preparing ${BURNS} one-view secrets for the burn run ...`);
  const ids = [];
  for (let i = 0; i < BURNS; i += 50) {
    ids.push(...await Promise.all(Array.from({ length: Math.min(50, BURNS - i) },
      () => createSecret({ secret: "benchmark-burn", ttl_seconds: 600, max_views: 1 }))));
  }
  let next = 0;
  console.log(`burn   c=${c0} (${BURNS} secrets, each burned once) ...`);
  rows.push(row("burn (write)", c0, await run({
    url: BASE, connections: c0, amount: BURNS,
    requests: [{ method: "POST", setupRequest: (req) => ({ ...req, path: `/api/secret/${ids[next++]}/burn` }) }],
  })));

  console.table(rows);

  const reads = rows.filter((r) => r.scenario === "view (read)");
  for (const r of reads) {
    const ok = r["req/s"] > TARGET_RPS && r["p99 ms"] < TARGET_P99_MS && r["non-2xx"] === 0 && r.errors === 0;
    console.log(`target (> ${TARGET_RPS} req/s, p99 < ${TARGET_P99_MS} ms) @ c=${r.connections}: ${ok ? "MET" : "NOT MET"}`
      + `  (${r["req/s"]} req/s, p99 ${r["p99 ms"]} ms)`);
  }
  const burn = rows.find((r) => r.scenario === "burn (write)");
  console.log(`burn run: ${burn["non-2xx"] === 0 ? "every secret burned exactly once" : `${burn["non-2xx"]} non-2xx responses`}`);
})().catch((e) => { console.error(e.message); process.exit(1); });
