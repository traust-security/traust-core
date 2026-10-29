// Shared building blocks for the ops API load scenarios (ops.js, breakpoint.js).
import http from 'k6/http';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

export const BASE = __ENV.BASE_URL || 'http://127.0.0.1:8080';
export const RUNNER = { headers: { Authorization: `Bearer ${__ENV.RUNNER_TOKEN}`, 'Content-Type': 'application/json' } };
export const READER = { headers: { Authorization: `Bearer ${__ENV.READER_TOKEN}` } };

export const claimOk = new Rate('claim_ok');
export const claimLatency = new Trend('claim_latency', true);
export const listLatency = new Trend('list_latency', true);
export const feedLatency = new Trend('feed_latency', true);
// Counters, not Trends: only counters carry a rate into the summary
export const claimReqs = new Counter('claim_requests');
export const listReqs = new Counter('list_requests');
export const feedReqs = new Counter('feed_requests');

export function claim() {
  const res = http.post(`${BASE}/v1/orders/claim`, JSON.stringify({ lease_seconds: 300 }), RUNNER);
  const ok = res.status === 200 || res.status === 204;
  claimOk.add(ok);
  claimLatency.add(res.timings.duration);
  claimReqs.add(1);
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
  listReqs.add(1);
  check(res, { 'list is 200': (r) => r.status === 200 });
}

export function readFeed() {
  const res = http.get(`${BASE}/v1/feed?limit=100`, READER);
  feedLatency.add(res.timings.duration);
  feedReqs.add(1);
  check(res, { 'feed is 200': (r) => r.status === 200 });
}

// Latency plus per-scenario request rates, so a run that collapsed to near-zero throughput
// cannot pass on flat latency alone.
export function summary(data, extra = {}) {
  const p95 = (m) => (data.metrics[m] ? data.metrics[m].values['p(95)'] : null);
  const rate = (m) => (data.metrics[m] ? data.metrics[m].values.rate : null);
  return {
    claim_p95_ms: p95('claim_latency'),
    list_p95_ms: p95('list_latency'),
    feed_p95_ms: p95('feed_latency'),
    claim_rps: rate('claim_requests'),
    list_rps: rate('list_requests'),
    feed_rps: rate('feed_requests'),
    http_reqs_rate: rate('http_reqs'),
    ...extra,
  };
}
