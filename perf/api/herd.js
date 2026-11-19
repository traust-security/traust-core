// The herd: HERD users (default 50) land on the dashboard's landing card at the same instant,
// each over their own grant, in WAVES waves WAVE_GAP seconds apart (the first wave is exactly
// simultaneous). The landing card is one query shape; the grants differ per user (a few
// repositories, a 366-repository grant, or the whole estate, at user-specific offsets).
// Correctness gate here (no failures); latency is reported by run.py --herd, no gate.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';
import { BASE, READER_JSON, p95Of, repositoryIds, setup as baseSetup } from './lib.js';

const HERD = Number(__ENV.HERD || 50);
const WAVES = Number(__ENV.WAVES || 5);
const WAVE_GAP = Number(__ENV.WAVE_GAP || 10);
const GRANT = 366;

const herdLatency = new Trend('herd_latency', true);

const LANDING = { measures: ['findings'], group_by: ['severity'], where: { state: ['open'] } };

export const options = {
  scenarios: {
    herd: { executor: 'per-vu-iterations', vus: HERD, iterations: WAVES, maxDuration: '10m' },
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
function grantOf(vu, repositories) {
  const offset = (vu * 37) % (repositories.length - GRANT);
  const size = [3, GRANT, 0][vu % 3];
  return size ? repositories.slice(offset, offset + size) : [];
}

export default function (data) {
  const started = Date.now();
  const body = { subject: 'findings', repository_ids: grantOf(__VU, data.repositories), ...LANDING };
  const res = http.post(`${BASE}/v1/dashboards:query`, JSON.stringify(body), READER_JSON);
  herdLatency.add(res.timings.duration);
  if (res.status !== 200) {
    console.log(`herd ${__VU} ${res.status} ${String(res.body).slice(0, 200)}`);
  }
  check(res, { 'landing card is 200': (r) => r.status === 200 });
  sleep(Math.max(0, WAVE_GAP - (Date.now() - started) / 1000));
}

export function handleSummary(data) {
  const values = data.metrics.herd_latency ? data.metrics.herd_latency.values : {};
  const failed = data.metrics.http_req_failed ? data.metrics.http_req_failed.values.rate : null;
  const out = {
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
