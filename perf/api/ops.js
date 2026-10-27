// Ops REST API load: 50 runners claim/complete while readers page orders and the feed.
// Run through perf/api/run.py (seeds Postgres, starts traust-server, mints tokens, compares
// the result to perf/api/baseline.json). Targets come from the folder README.
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const RUNNER = {
  headers: { Authorization: `Bearer ${__ENV.RUNNER_TOKEN}`, 'Content-Type': 'application/json' },
};
const READER = { headers: { Authorization: `Bearer ${__ENV.READER_TOKEN}` } };

const claimOk = new Rate('claim_ok');
const claimLatency = new Trend('claim_latency', true);
const listLatency = new Trend('list_latency', true);
const feedLatency = new Trend('feed_latency', true);

const DURATION = __ENV.DURATION || '20s';

export const options = {
  scenarios: {
    claim_contention: { executor: 'constant-vus', vus: 50, duration: DURATION, exec: 'claim' },
    order_reads: { executor: 'constant-vus', vus: 10, duration: DURATION, exec: 'listOrders' },
    feed_reads: { executor: 'constant-vus', vus: 10, duration: DURATION, exec: 'readFeed' },
  },
  // Correctness gates fail the run here; latency is gated against baseline.json by run.py
  // (a run more than 20% slower fails), since absolute p95 depends on the host.
  thresholds: {
    claim_ok: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
  },
};

export function claim() {
  const res = http.post(`${BASE}/v1/orders/claim`, JSON.stringify({ lease_seconds: 300 }), RUNNER);
  const ok = res.status === 200 || res.status === 204;
  claimOk.add(ok);
  claimLatency.add(res.timings.duration);
  check(res, { 'claim is 200 or 204': () => ok });
  if (res.status === 200) {
    // finish the lease so the queue keeps flowing and a later claim can reach the head
    const id = res.json('id');
    const done = { result: { outcome: 'succeeded' } };
    http.post(`${BASE}/v1/orders/${id}/complete`, JSON.stringify(done), RUNNER);
  }
}

export function listOrders() {
  const res = http.get(`${BASE}/v1/orders?states=queued&limit=50`, READER);
  listLatency.add(res.timings.duration);
  check(res, { 'list is 200': (r) => r.status === 200 });
}

export function readFeed() {
  const res = http.get(`${BASE}/v1/feed?limit=100`, READER);
  feedLatency.add(res.timings.duration);
  check(res, { 'feed is 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  const p95 = (m) => (data.metrics[m] ? data.metrics[m].values['p(95)'] : null);
  const rate = (m) => (data.metrics[m] ? data.metrics[m].values.rate : null);
  const out = {
    claim_p95_ms: p95('claim_latency'),
    list_p95_ms: p95('list_latency'),
    feed_p95_ms: p95('feed_latency'),
    claim_ok_rate: rate('claim_ok'),
    http_req_failed_rate: rate('http_req_failed'),
  };
  return { [__ENV.SUMMARY || '.perf/api-summary.json']: JSON.stringify(out, null, 2) };
}
