import test from 'node:test';
import assert from 'node:assert/strict';

const base = process.env.PUBLIC_SITE_BASE_URL ?? 'http://127.0.0.1:8787';

async function request(path, options) {
  return fetch(new URL(path, base), { redirect: 'manual', ...options });
}

test('static pages keep the public browser boundary', async () => {
  for (const path of ['/', '/privacy']) {
    const response = await request(path);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-security-policy') ?? '', /connect-src 'none'/);
    assert.match(response.headers.get('content-security-policy') ?? '', /frame-ancestors 'none'/);
    assert.equal(response.headers.get('set-cookie'), null);
    const html = await response.text();
    assert.doesNotMatch(html, /<form\b|<iframe\b|\bsrc=["']https?:\/\//i);
  }
});

test('status reports the approved native profile without browser RPC access', async () => {
  const response = await request('/api/status');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const status = await response.json();
  assert.equal(status.kind, 'repository_snapshot');
  assert.equal(status.release_approval.state, 'phala_trusted_testnet_approved');
  assert.equal(status.transport_attestation.state, 'not_checked');
  assert.equal(status.payment.state, 'free_tickets_required');
  assert.equal(status.chain_data.state, 'live_testnet_query_recorded');

  const capabilities = await (await request('/api/capabilities')).json();
  assert.equal(capabilities.trusted_release_policy_from_website, false);
  assert.equal(capabilities.private_rpc_from_website, false);
  assert.equal(capabilities.ticket_handling_from_website, false);
  assert.deepEqual(capabilities.methods, ['getblockchaininfo', 'getblockcount']);
});

test('API rejects input, cross-origin access, and unknown routes', async () => {
  const cases = [
    ['/api/status?txid=abc', undefined, 400],
    ['/api/status', { method: 'POST', body: 'secret' }, 405],
    ['/api/status', { headers: { Origin: 'https://other.example' } }, 403],
    ['/api/status', { headers: { 'Sec-Fetch-Site': 'cross-site' } }, 403],
    ['/api/scenarios/success', undefined, 404],
    ['/api/proxy', undefined, 404]
  ];
  for (const [path, options, status] of cases) {
    const response = await request(path, options);
    assert.equal(response.status, status, path);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
    const body = await response.text();
    assert.doesNotMatch(body, /secret|txid=abc/i);
  }
});
