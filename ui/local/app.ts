export {};

type Report = {
  simulation: boolean; private_accepted: boolean; query_sent: boolean | string; fixture_dispatched?: boolean;
  verification?: Record<string, unknown>; chain_readiness?: unknown;
  error: unknown; result: unknown;
};
const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error('Bundled UI is incomplete');
  return element as T;
};
const run = byId<HTMLButtonElement>('run');
const session = byId('session');
let capability = '';
let mode: 'simulation' | 'live_unverified' = 'simulation';
let bootstrap = location.hash.slice(1);
history.replaceState(null, '', location.pathname);

async function api(path: string, body?: string, scenario?: string): Promise<unknown> {
  const response = await fetch(path, {
    method: 'POST', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
    headers: { 'Authorization': `Bearer ${capability}`, 'Content-Type': 'application/json', ...(scenario ? {'X-Zrpc-Scenario':scenario} : {}) },
    body: body ?? '{}'
  });
  if (!response.ok) throw new Error('Local client rejected this request. Restart the dashboard from the CLI.');
  return response.json();
}
function show(report: Report, elapsed: number): void {
  byId('result').textContent = JSON.stringify(report, null, 2);
  byId('sent').textContent = report.query_sent === true ? 'Yes' : report.query_sent === false ? 'No' : 'Unknown';
  byId('chain').textContent = String(report.chain_readiness ?? 'not_checked').replaceAll('_', ' ');
  byId('latency').textContent = `${elapsed.toFixed(1)} ms`;
  byId('result-label').textContent = mode === 'simulation'
    ? (report.error ? 'SIMULATED REJECTION' : 'SYNTHETIC RESULT')
    : (report.private_accepted === true && report.query_sent === true && !report.error
      ? 'VERIFIED RESPONSE' : report.private_accepted === true ? 'QUERY FAILED' : 'PRIVATE MODE BLOCKED');
  const evidence = byId('evidence');
  evidence.replaceChildren();
  const labels: Record<string,string> = {transport:'Transport',hardware:'Hardware authenticity',application:'Application policy',key_binding:'Connection key',freshness:'Freshness',release:'Release approval'};
  for (const [key, label] of Object.entries(labels)) {
    const row = document.createElement('div');
    const name = document.createElement('dt'); name.textContent = label;
    const value = document.createElement('dd');
    const status = report.verification?.[key];
    value.textContent = typeof status === 'string' ? status.replaceAll('_',' ') : 'not checked';
    row.append(name, value); evidence.append(row);
  }
}
run.addEventListener('click', async () => {
  run.disabled = true;
  const method = byId<HTMLSelectElement>('method').value;
  const params = method === 'getblockhash' ? [42] : ['getblockheader','getrawtransaction'].includes(method) ? [method === 'getrawtransaction' ? 'b'.repeat(64) : 'a'.repeat(64), true] : [];
  const request = JSON.stringify({jsonrpc:'2.0',id:1,method,params});
  const started = performance.now();
  try { show(await api('/api/query', request, mode === 'simulation' ? byId<HTMLSelectElement>('scenario').value : undefined) as Report, performance.now()-started); }
  catch (error) { session.textContent = error instanceof Error ? error.message : 'Local request failed'; }
  finally { run.disabled = false; }
});
async function start(): Promise<void> {
  try {
    if (!/^[a-f0-9]{64}$/.test(bootstrap)) throw new Error('Open this dashboard from the zrpc CLI to establish a local session.');
    capability = bootstrap;
    const result = await api('/api/bootstrap') as {capability:string;mode:'simulation'|'live_unverified';platform?:string};
    capability = result.capability;
    mode = result.mode;
    bootstrap = '';
    if (mode === 'live_unverified') {
      byId('mode-label').textContent = 'LIVE CLIENT · UNVERIFIED';
      byId('mode-description').textContent = 'This dashboard can ask the native client to verify a remote endpoint. No private query is sent unless the independently reviewed release and live connection pass every check.';
      byId('method-label').textContent = 'Typed testnet request';
      byId('scenario-label').style.display = 'none';
      byId('scenario').style.display = 'none';
      for (const option of Array.from(byId<HTMLSelectElement>('method').options)) {
        if (!['getblockcount','getblockchaininfo'].includes(option.value)) option.disabled = true;
      }
      run.firstChild!.textContent = 'Try verified query ';
      byId('release-note').textContent = `${result.platform === 'gcp-tdx' ? 'Google Cloud TDX' : 'Phala dstack'}: no approved production release is packaged yet. Private mode stays blocked.`;
      session.textContent = 'Local session ready. Private mode requires independent verification.';
    } else {
      byId('mode-label').textContent = 'SIMULATION ONLY';
      byId('mode-description').textContent = 'No hardware attestation, Tor connection, cloud service or live blockchain. Fixtures never authorize private mode.';
      session.textContent = 'Local session ready. Simulation fixtures stay on this device.';
    }
    run.disabled = false;
  } catch (error) {
    capability = ''; bootstrap = '';
    session.textContent = error instanceof Error ? error.message : 'Local session failed';
  }
}
void start();
