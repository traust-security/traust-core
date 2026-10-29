// Ops REST API load: 50 runners claim/complete while readers page orders and the feed.
// Run through perf/api/run.py (seeds Postgres, starts traust-server, mints tokens, compares
// the result to perf/api/baseline.json). Targets come from the folder README.
import { claim, listOrders, readFeed, summary } from './lib.js';

const DURATION = __ENV.DURATION || '20s';

export const options = {
  scenarios: {
    claim_contention: { executor: 'constant-vus', vus: 50, duration: DURATION, exec: 'claim' },
    order_reads: { executor: 'constant-vus', vus: 10, duration: DURATION, exec: 'listOrders' },
    feed_reads: { executor: 'constant-vus', vus: 10, duration: DURATION, exec: 'readFeed' },
  },
  // Correctness gates fail the run here; latency and throughput are gated against baseline.json
  // by run.py (a run more than 20% slower, or more than 20% lower throughput, fails), since
  // absolute p95 depends on the host.
  thresholds: {
    claim_ok: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
  },
};

export { claim, listOrders, readFeed };

export function handleSummary(data) {
  return { [__ENV.SUMMARY || '.perf/api-summary.json']: JSON.stringify(summary(data), null, 2) };
}
