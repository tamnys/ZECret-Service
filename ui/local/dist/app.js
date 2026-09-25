const byId = (id) => {
    const element = document.getElementById(id);
    if (!element)
        throw new Error('Bundled UI is incomplete');
    return element;
};
const run = byId('run');
const session = byId('session');
let capability = '';
let bootstrap = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
async function api(path, body, scenario) {
    const response = await fetch(path, {
        method: 'POST', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
        headers: { 'Authorization': `Bearer ${capability}`, 'Content-Type': 'application/json', ...(scenario ? { 'X-Zrpc-Scenario': scenario } : {}) },
        body: body ?? '{}'
    });
    if (!response.ok)
        throw new Error('Local client rejected this request. Restart the dashboard from the CLI.');
    return response.json();
}
function show(report, elapsed) {
    byId('result').textContent = JSON.stringify(report, null, 2);
    byId('sent').textContent = report.query_sent ? 'Unexpected dispatch' : 'No';
    byId('chain').textContent = String(report.chain_readiness).replaceAll('_', ' ');
    byId('latency').textContent = `${elapsed.toFixed(1)} ms`;
    byId('result-label').textContent = report.error ? 'SIMULATED REJECTION' : 'SYNTHETIC RESULT';
    const evidence = byId('evidence');
    evidence.replaceChildren();
    const labels = { transport: 'Transport', hardware: 'Hardware authenticity', application: 'Application policy', key_binding: 'Connection key', freshness: 'Freshness' };
    for (const [key, label] of Object.entries(labels)) {
        const row = document.createElement('div');
        const name = document.createElement('dt');
        name.textContent = label;
        const value = document.createElement('dd');
        const status = report.verification[key];
        value.textContent = typeof status === 'string' ? status.replaceAll('_', ' ') : JSON.stringify(status ?? 'not_checked');
        row.append(name, value);
        evidence.append(row);
    }
}
run.addEventListener('click', async () => {
    run.disabled = true;
    const method = byId('method').value;
    const params = method === 'getblockhash' ? [42] : ['getblockheader', 'getrawtransaction'].includes(method) ? [method === 'getrawtransaction' ? 'b'.repeat(64) : 'a'.repeat(64), true] : [];
    const request = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const started = performance.now();
    try {
        show(await api('/api/query', request, byId('scenario').value), performance.now() - started);
    }
    catch (error) {
        session.textContent = error instanceof Error ? error.message : 'Local request failed';
    }
    finally {
        run.disabled = false;
    }
});
async function start() {
    try {
        if (!/^[a-f0-9]{64}$/.test(bootstrap))
            throw new Error('Open this dashboard from zrpc demo to establish a local session.');
        capability = bootstrap;
        const result = await api('/api/bootstrap');
        capability = result.capability;
        bootstrap = '';
        session.textContent = 'Local session ready. All requests stay on this device.';
        run.disabled = false;
    }
    catch (error) {
        capability = '';
        bootstrap = '';
        session.textContent = error instanceof Error ? error.message : 'Local session failed';
    }
}
void start();
export {};
