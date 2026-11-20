// The herd: HERD users (default 50) hit one read at the same instant, each over their own
// scope, in WAVES waves WAVE_GAP seconds apart (the first wave is exactly simultaneous).
// TARGET picks the read (default: the dashboard's landing card); the sweep runs every read
// SCI calls this way to find the ones that collapse under a herd. Scopes differ per user (a
// few repositories, a larger grant, or the whole estate, at user-specific offsets).
// Correctness gate here (no failures); latency is reported by run.py --herd, no gate.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';
import { BASE, READER, READER_JSON, p95Of, repositoryIds, setup as baseSetup } from './lib.js';

const HERD = Number(__ENV.HERD || 50);
const WAVES = Number(__ENV.WAVES || 5);
const WAVE_GAP = Number(__ENV.WAVE_GAP || 10);
const GRANT = 366;
const TARGET = __ENV.TARGET || 'dashboard';

const herdLatency = new Trend('herd_latency', true);

const LANDING = { measures: ['findings'], group_by: ['severity'], where: { state: ['open'] } };

export const options = {
  scenarios: {
    herd: {
      executor: 'per-vu-iterations',
      vus: HERD,
      iterations: WAVES,
      maxDuration: __ENV.MAX_DURATION || '10m',
    },
  },
  thresholds: { http_req_failed: ['rate<0.01'] },
};

export function setup() {
  const repositories = repositoryIds();
  if (repositories.length < GRANT + HERD) {
    throw new Error(`the rig has ${repositories.length} repositories; the herd needs ${GRANT + HERD}`);
  }
  return { ...baseSetup(), repositories };
}

// A user's grant: a third of the herd each hold a few repositories, a 366-repository grant,
// or the whole estate (no ids), each at an offset of their own so no two grants coincide.
function grantOf(vu, repositories, large = GRANT) {
  const offset = (vu * 37) % (repositories.length - GRANT);
  const size = [3, large, 0][vu % 3];
  return size ? repositories.slice(offset, offset + size) : [];
}

// Query-string grants stay at 100 ids (a 366-id URL outgrows request-line limits), and the
// findings lists refuse an empty scope by design, so their third scope is a second 100-id grant.
const ids = (grant) => grant.map((id) => `repository_ids=${id}`).join('&');
function named(vu, repositories) {
  const offset = (vu * 37) % (repositories.length - GRANT);
  const size = [3, 100, 100][vu % 3];
  const start = vu % 3 === 2 ? (offset + GRANT) % (repositories.length - 100) : offset;
  return repositories.slice(start, start + size);
}
const one = (vu, data) => data.repositories[(vu * 37) % data.repositories.length];

// One request per read SCI calls: [method, path, body].
const READS = {
  dashboard: (vu, d) => ['POST', '/v1/dashboards:query',
    { subject: 'findings', repository_ids: grantOf(vu, d.repositories), ...LANDING }],
  findings_page: (vu, d) => ['GET', `/v1/findings?limit=100&${ids(named(vu, d.repositories))}`],
  findings_count: (vu, d) => ['GET', `/v1/findings/count?${ids(named(vu, d.repositories))}`],
  findings_summaries: (vu, d) => ['GET', `/v1/findings/summaries?${ids(named(vu, d.repositories))}`],
  review_queue: (vu, d) => ['GET', `/v1/findings/review-queue?repository_id=${one(vu, d)}`],
  repo_findings: (vu, d) => ['GET', `/v1/repositories/${one(vu, d)}/findings?limit=100`],
  repo_summary: (vu, d) => ['GET', `/v1/repositories/${one(vu, d)}/findings/summary?group_by=severity`],
  repo_timeline: (vu, d) => ['GET', `/v1/repositories/${one(vu, d)}/findings/timeline`],
  report_request: (vu, d) => ['POST', '/v1/reports', { report: 'findings-rollup', scope: { product_ids: [d.product] } }],
  feed: () => ['GET', '/v1/feed?limit=100'],
  orders: () => ['GET', '/v1/orders?states=queued&limit=50'],
};

export default function (data) {
  const started = Date.now();
  const [method, path, body] = READS[TARGET](__VU, data);
  const res = method === 'POST'
    ? http.post(`${BASE}${path}`, JSON.stringify(body), READER_JSON)
    : http.get(`${BASE}${path}`, READER);
  herdLatency.add(res.timings.duration);
  if (res.status !== 200) {
    console.log(`herd ${TARGET} ${__VU} ${res.status} ${String(res.body).slice(0, 200)}`);
  }
  check(res, { 'read is 200': (r) => r.status === 200 });
  sleep(Math.max(0, WAVE_GAP - (Date.now() - started) / 1000));
}

export function handleSummary(data) {
  const values = data.metrics.herd_latency ? data.metrics.herd_latency.values : {};
  const failed = data.metrics.http_req_failed ? data.metrics.http_req_failed.values.rate : null;
  const out = {
    herd_target: TARGET,
    herd_users: HERD,
    herd_waves: WAVES,
    herd_p50_ms: values.med ?? null,
    herd_p95_ms: p95Of(data, 'herd_latency'),
    herd_max_ms: values.max ?? null,
    herd_requests: data.metrics.http_reqs ? data.metrics.http_reqs.values.count : null,
    herd_failed_rate: failed,
  };
  return { [__ENV.SUMMARY || '.perf/api-herd.json']: JSON.stringify(out, null, 2) };
}
