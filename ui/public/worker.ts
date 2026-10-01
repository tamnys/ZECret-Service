/** Public, deterministic website API. It has no RPC, ticket, wallet, or status upstream. */

const SOURCE = 'https://github.com/tamnys/ZECret-Service';
const SNAPSHOT_DATE = '2026-10-01';

const status = {
  kind: 'repository_snapshot',
  as_of: SNAPSHOT_DATE,
  source: `${SOURCE}/blob/main/records/phala-block-context-rollout-2026-10-01.md`,
  release_approval: {
    state: 'phala_trusted_testnet_approved',
    detail: 'An approved Phala-trusting testnet release is packaged in the native client. The stricter provider-independent private profile remains unavailable.'
  },
  transport_attestation: {
    state: 'not_checked',
    detail: 'A public website cannot verify a native Tor and attested TLS session.'
  },
  payment: {
    state: 'local_poc_only',
    detail: 'Tickets remain a separate local proof of concept. The approved Phala-trusting testnet service does not accept ticket payments.'
  },
  chain_data: {
    state: 'live_testnet_query_recorded',
    detail: 'A native client completed a live Zcash testnet query on 2026-10-01. This dated snapshot does not report current service health.'
  }
} as const;

const capabilities = {
  kind: 'informational_only',
  as_of: SNAPSHOT_DATE,
  methods: ['getblockchaininfo', 'getblockcount', 'getblockhash', 'getblockheader', 'getrawtransaction', 'getaddressbalance'],
  private_rpc_from_website: false,
  ticket_handling_from_website: false,
  trusted_release_policy_from_website: false,
  source: `${SOURCE}/blob/main/crates/protocol/src/lib.rs`
} as const;

const scenarios = {
  success: {
    kind: 'synthetic_fixture',
    title: 'Example response',
    explanation: 'A canned block-height response illustrates the shape of a successful native query. No connection or attestation occurred.',
    simulated_decision: 'accepted_in_fixture',
    real_private_query_sent: false,
    payment: 'not_used',
    chain_data: { kind: 'synthetic_fixture', method: 'getblockcount', block_height: 42 }
  },
  'release-rejected': {
    kind: 'synthetic_fixture',
    title: 'Release rejected',
    explanation: 'The example client refuses before a query when the workload does not match its independently trusted release policy.',
    simulated_decision: 'rejected_in_fixture',
    reason: 'unknown_release',
    real_private_query_sent: false,
    chain_data: null
  },
  'ticket-replay': {
    kind: 'payment_simulation',
    title: 'Ticket replay rejected',
    explanation: 'This synthetic ticket was already spent, so the illustrated service rejects its replay. Native ticket issuance and redemption have been tested locally; paid access is not live.',
    simulated_decision: 'rejected_in_fixture',
    reason: 'ticket_already_spent',
    real_private_query_sent: false,
    payment: 'simulated_only',
    chain_data: null
  }
} as const;

const HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
} as const;

function json(value: unknown, code = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(value), {
    status: code,
    headers: { ...HEADERS, ...extraHeaders }
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }

    // The API is public but intentionally usable only by this site in browsers.
    const origin = request.headers.get('Origin');
    if ((origin && origin !== url.origin) || request.headers.get('Sec-Fetch-Site') === 'cross-site') {
      return json({ error: 'Cross-origin API access is unavailable.' }, 403);
    }
    if (request.method !== 'GET') {
      return json({ error: 'Use GET for this public endpoint.' }, 405, { Allow: 'GET' });
    }
    if (url.search || request.body !== null) {
      return json({ error: 'This endpoint does not accept input.' }, 400);
    }
    if (url.pathname === '/api/status') return json(status);
    if (url.pathname === '/api/capabilities') return json(capabilities);
    if (url.pathname === '/api/scenarios') {
      return json({ kind: 'synthetic_fixture_index', scenarios: Object.keys(scenarios) });
    }
    const match = /^\/api\/scenarios\/([a-z-]+)$/.exec(url.pathname);
    if (match && Object.prototype.hasOwnProperty.call(scenarios, match[1])) {
      return json(scenarios[match[1] as keyof typeof scenarios]);
    }
    return json({ error: 'Public endpoint not found.' }, 404);
  }
};
