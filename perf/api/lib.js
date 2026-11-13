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
export const insightLatency = new Trend('insight_latency', true);
export const insightReqs = new Counter('insight_requests');
export const consumerLatency = new Trend('consumer_latency', true);
export const consumerReqs = new Counter('consumer_requests');

// The consumer read family: a hot repository's findings paged by cursor, its summary and
// timeline, and the review queue — the shapes SCI and the CLI read under load.
export function pageFindings(data) {
  const first = http.get(
    `${BASE}/v1/repositories/${data.repository}/findings?limit=100`,
    READER
  );
  consumerLatency.add(first.timings.duration);
  consumerReqs.add(1);
  check(first, { 'findings page is 200': (r) => r.status === 200 });
  const next = first.json('next');
  if (next) {
    const second = http.get(
      `${BASE}/v1/repositories/${data.repository}/findings?limit=100&cursor=${encodeURIComponent(next)}`,
      READER
    );
    consumerLatency.add(second.timings.duration);
    consumerReqs.add(1);
    check(second, { 'findings next page is 200': (r) => r.status === 200 });
  }
}

export function readSummary(data) {
  const res = http.get(
    `${BASE}/v1/repositories/${data.repository}/findings/summary?group_by=cwe`,
    READER
  );
  consumerLatency.add(res.timings.duration);
  consumerReqs.add(1);
  check(res, { 'summary is 200': (r) => r.status === 200 });
}

export function readTimeline(data) {
  const res = http.get(`${BASE}/v1/repositories/${data.repository}/findings/timeline`, READER);
  consumerLatency.add(res.timings.duration);
  consumerReqs.add(1);
  check(res, { 'timeline is 200': (r) => r.status === 200 });
}

export function readReviewQueue() {
  const res = http.get(`${BASE}/v1/findings/review-queue?limit=100`, READER);
  consumerLatency.add(res.timings.duration);
  consumerReqs.add(1);
  check(res, { 'review queue is 200': (r) => r.status === 200 });
}

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

export function setup() {
  const res = http.get(`${BASE}/v1/products?limit=1`, READER);
  if (res.status !== 200) {
    console.log(`products ${res.status} ${JSON.stringify(res.error)} ${String(res.body).slice(0, 200)}`);
  }
  check(res, { 'products list is 200': (r) => r.status === 200 });
  const product = res.json('items.0.id');
  if (!product) {
    throw new Error('no product to scope the insight read to');
  }
  // a repository with findings to page: the first the products page's scope admits, else the
  // fleet's first — the scenarios only need a real, non-empty read shape
  const found = http.get(`${BASE}/v1/repositories?limit=1`, READER);
  const repository = found.json('items.0.id');
  if (!repository) {
    throw new Error('no repository to page findings of');
  }
  return { product, repository };
}

// The dashboard's heaviest view family: an insight built on demand. Scoped to one product so
// the read is request-shaped (the whole-portfolio cost is bounded by perf/queries, which sees
// the statements); unscoped at fixture volume the build runs to minutes, not a gateable request.
export function readInsight(data) {
  const res = http.get(`${BASE}/v1/insights/findings-rollup?product_id=${data.product}`, READER);
  insightLatency.add(res.timings.duration);
  insightReqs.add(1);
  if (res.status !== 200) {
    console.log(`insight ${res.status} ${JSON.stringify(res.error)} ${String(res.body).slice(0, 200)}`);
  }
  check(res, { 'insight is 200': (r) => r.status === 200 });
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
    insight_p95_ms: p95('insight_latency'),
    consumer_p95_ms: p95('consumer_latency'),
    claim_rps: rate('claim_requests'),
    list_rps: rate('list_requests'),
    feed_rps: rate('feed_requests'),
    insight_rps: rate('insight_requests'),
    consumer_rps: rate('consumer_requests'),
    http_reqs_rate: rate('http_reqs'),
    ...extra,
  };
}
