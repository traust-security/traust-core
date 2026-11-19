// Ops REST API load: runners claim/complete while readers page orders, the feed, one insight
// view, the consumer read family, and the dashboard personas — a persona is a grant × an app
// area × a cadence (the findings subject only, until review_items and work_items land): a
// poll persona re-reads its card at its own cadence like an open tab, a visit persona reads
// once like a person opening a page. Scenario weights live here alone (the README describes
// what, not how many). Run through perf/api/run.py (seeds Postgres, starts traust-server,
// mints tokens, compares the result to perf/api/baseline.json).
import {
  claim,
  listOrders,
  pageFindings,
  p95Of,
  queryDashboard,
  rateOf,
  readFeed,
  readInsight,
  readReviewQueue,
  readSummary,
  readTimeline,
  repositoryIds,
  setup as baseSetup,
  summary,
} from './lib.js';

const DURATION = __ENV.DURATION || '20s';

// The card shapes the dashboard route serves; grants are slices of the repository list setup
// fetches, and no repository_ids is the whole estate.
const CARDS = {
  measure: { measures: ['findings'] },
  severity: { measures: ['findings'], group_by: ['severity'] },
  category: { measures: ['findings'], group_by: ['category'] },
  top: {
    measures: ['findings'],
    group_by: ['repository'],
    order: [{ by: 'findings', desc: true }],
    limit: 10,
  },
  filtered: {
    measures: ['findings'],
    group_by: ['severity'],
    where: { state: ['open'], severity: ['critical', 'high'] },
  },
};

const SMALL = [0, 3];
const ANOTHER_SMALL = [500, 503];
const GRANT_366 = [0, 366];
const ANOTHER_366 = [400, 766];

const PERSONAS = [
  // poll personas: tabs re-reading their card at their own cadence
  { name: 'small-measure-tab', grant: SMALL, card: 'measure', cadence: '30s' },
  { name: 'small-severity-tab', grant: SMALL, card: 'severity', cadence: '30s' },
  { name: 'small-category-tab', grant: SMALL, card: 'category', cadence: '30s' },
  { name: 'small-top-tab', grant: SMALL, card: 'top', cadence: '15s' },
  { name: 'small-filtered-tab', grant: SMALL, card: 'filtered', cadence: '30s' },
  { name: 'grant366-measure-tab', grant: GRANT_366, card: 'measure', cadence: '30s' },
  { name: 'grant366-severity-tab', grant: GRANT_366, card: 'severity', cadence: '30s' },
  { name: 'grant366-category-tab', grant: GRANT_366, card: 'category', cadence: '60s' },
  { name: 'grant366-top-tab', grant: GRANT_366, card: 'top', cadence: '30s' },
  { name: 'grant366-filtered-tab', grant: GRANT_366, card: 'filtered', cadence: '30s' },
  { name: 'estate-measure-tab', grant: null, card: 'measure', cadence: '30s' },
  { name: 'estate-severity-tab', grant: null, card: 'severity', cadence: '30s' },
  { name: 'estate-category-tab', grant: null, card: 'category', cadence: '60s' },
  { name: 'estate-top-tab', grant: null, card: 'top', cadence: '30s' },
  { name: 'estate-filtered-tab', grant: null, card: 'filtered', cadence: '30s' },
  // visit personas: one read, like a person opening a page
  { name: 'small-top-visit', grant: ANOTHER_SMALL, card: 'top', once: true },
  { name: 'small-filtered-visit', grant: SMALL, card: 'filtered', once: true },
  { name: 'grant366-category-visit', grant: ANOTHER_366, card: 'category', once: true },
  { name: 'grant366-measure-visit', grant: GRANT_366, card: 'measure', once: true },
  { name: 'estate-measure-visit', grant: null, card: 'measure', once: true },
  { name: 'estate-severity-visit', grant: null, card: 'severity', once: true },
];

// A persona's scenario group: a staggered start (requests land at different times, like users
// spread across an app), each at its own cadence — one request per cadence for a tab, a
// single read for a visit. The scenario's env names the persona to queryDashboard.
function personaScenario(persona, index) {
  const common = { exec: 'queryDashboard', env: { PERSONA: persona.name } };
  if (persona.once) {
    return {
      ...common,
      executor: 'per-vu-iterations',
      vus: 1,
      iterations: 1,
      startTime: `${1 + index * 2}s`,
    };
  }
  return {
    ...common,
    executor: 'constant-arrival-rate',
    rate: 1,
    timeUnit: persona.cadence,
    duration: DURATION,
    preAllocatedVUs: 1,
    maxVUs: 2,
    startTime: `${index * 2}s`,
  };
}

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
    ...Object.fromEntries(PERSONAS.map((p, i) => [`dashboard_${p.name}`, personaScenario(p, i)])),
  },
  // Correctness gates fail the run here; latency and throughput are gated against baseline.json
  // by run.py (a run more than 20% slower, or more than 20% lower throughput, fails), since
  // absolute p95 depends on the host.
  thresholds: {
    claim_ok: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
  },
};

export function setup() {
  const data = baseSetup();
  const repositories = repositoryIds();
  const needed = Math.max(...PERSONAS.map((p) => (p.grant ? p.grant[1] : 0)));
  if (repositories.length < needed) {
    throw new Error(`the rig has ${repositories.length} repositories; the personas need ${needed}`);
  }
  const bodies = {};
  for (const persona of PERSONAS) {
    bodies[persona.name] = {
      subject: 'findings',
      repository_ids: persona.grant ? repositories.slice(persona.grant[0], persona.grant[1]) : [],
      ...CARDS[persona.card],
    };
  }
  return { ...data, bodies };
}

export {
  claim,
  listOrders,
  readFeed,
  readInsight,
  pageFindings,
  readSummary,
  readTimeline,
  readReviewQueue,
  queryDashboard,
};

export function handleSummary(data) {
  // One row pair per persona, so baseline.json gates each persona's latency and cadence.
  const personas = {};
  for (const persona of PERSONAS) {
    personas[`persona_${persona.name}_p95_ms`] = p95Of(data, `persona_${persona.name}_latency`);
    personas[`persona_${persona.name}_rps`] = rateOf(data, `persona_${persona.name}_requests`);
  }
  return { [__ENV.SUMMARY || '.perf/api-summary.json']: JSON.stringify(summary(data, personas), null, 2) };
}
