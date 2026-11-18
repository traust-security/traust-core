// Ops REST API load: runners claim/complete while readers page orders, the feed, one insight
// view and the consumer read family — a repository's findings (paged, summary, timeline) and
// the review queue. Scenario weights live here alone (the README describes what, not how many).
// Run through perf/api/run.py (seeds Postgres, starts traust-server, mints tokens, compares the
// result to perf/api/baseline.json).
import {
  claim,
  listOrders,
  readFeed,
  readInsight,
  readReviewQueue,
  readSummary,
  readTimeline,
  pageFindings,
  setup,
  summary,
} from './lib.js';

const DURATION = __ENV.DURATION || '20s';

export const options = {
  scenarios: {
    claim_contention: { executor: 'constant-vus', vus: 50, duration: DURATION, exec: 'claim' },
    order_reads: { executor: 'constant-vus', vus: 10, duration: DURATION, exec: 'listOrders' },
    feed_reads: { executor: 'constant-vus', vus: 10, duration: DURATION, exec: 'readFeed' },
    insight_reads: { executor: 'constant-vus', vus: 2, duration: DURATION, exec: 'readInsight' },
    findings_paging: { executor: 'constant-vus', vus: 5, duration: DURATION, exec: 'pageFindings' },
    findings_summary: { executor: 'constant-vus', vus: 3, duration: DURATION, exec: 'readSummary' },
    findings_timeline: { executor: 'constant-vus', vus: 3, duration: DURATION, exec: 'readTimeline' },
    review_queue: { executor: 'constant-vus', vus: 3, duration: DURATION, exec: 'readReviewQueue' },
  },
  // Correctness gates fail the run here; latency and throughput are gated against baseline.json
  // by run.py (a run more than 20% slower, or more than 20% lower throughput, fails), since
  // absolute p95 depends on the host.
  thresholds: {
    claim_ok: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
  },
};

export { claim, listOrders, readFeed, readInsight, pageFindings, readSummary, readTimeline, readReviewQueue, setup };

export function handleSummary(data) {
  return { [__ENV.SUMMARY || '.perf/api-summary.json']: JSON.stringify(summary(data), null, 2) };
}
