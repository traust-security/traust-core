// Discovery ramp: 50 runners keep claiming while the readers climb 10 -> 300 VUs, to find
// where the API stops holding. Not gated against a baseline; run.py prints where latency and
// throughput land. Run through perf/api/run.py --breakpoint (which also resets the order queue,
// so the ramp measures a queue, not an empty pool).
import { claim, listOrders, readFeed, summary } from './lib.js';

const CLAIM_VUS = 50;

export const options = {
  scenarios: {
    claim_contention: { executor: 'constant-vus', vus: CLAIM_VUS, duration: '75s', exec: 'claim' },
    reader_ramp: {
      executor: 'ramping-vus',
      startVUs: 10,
      stages: [
        { duration: '60s', target: 300 },
        { duration: '15s', target: 300 },
      ],
      exec: 'read',
    },
  },
  // Correctness gates only: a breakpoint run reports the edge, it does not fail on latency.
  thresholds: {
    claim_ok: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
  },
};

export { claim };

export function read() {
  listOrders();
  readFeed();
}

export function handleSummary(data) {
  // claims hold CLAIM_VUS for the whole run, so the rest of the peak is readers
  const maxVus = data.metrics.vus_max ? data.metrics.vus_max.values.max : null;
  const out = summary(data, { peak_readers: maxVus != null ? maxVus - CLAIM_VUS : null });
  return { [__ENV.SUMMARY || '.perf/api-breakpoint.json']: JSON.stringify(out, null, 2) };
}
