const byId = (id) => {
    const element = document.getElementById(id);
    if (!element)
        throw new Error('Bundled UI is incomplete');
    return element;
};
const run = byId('run');
const session = byId('session');
const methodSelect = byId('method');
let capability = '';
let mode = 'simulation';
let bootstrap = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
async function api(path, body, scenario) {
    const response = await fetch(path, {
        method: 'POST', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
        headers: { 'Authorization': `Bearer ${capability}`, 'Content-Type': 'application/json', ...(scenario ? { 'X-Zrpc-Scenario': scenario } : {}) },
        body
    });
    if (!response.ok)
        throw new Error(path.startsWith('/api/preview') && response.status === 400
            ? 'Enter a valid Zcash testnet transparent address.'
            : 'Local client rejected this request. Restart the dashboard from the CLI.');
    return response.json();
}
function renderEvidence(verification) {
    const evidence = byId('evidence');
    evidence.replaceChildren();
    const checks = [
        ['SOCKS path', verification?.transport],
        ['Hardware authenticity', verification?.hardware],
        [mode === 'live_testnet_preview' ? 'Workload identity' : 'Workload policy', verification?.workload ?? verification?.application],
        ['Connection key', verification?.channel_binding ?? verification?.key_binding],
        ['Freshness', verification?.freshness],
        ['Release approval', verification?.release_approval ?? verification?.release]
    ];
    for (const [label, status] of checks) {
        const row = document.createElement('div');
        const name = document.createElement('dt');
        name.textContent = label;
        const value = document.createElement('dd');
        value.textContent = typeof status === 'string' ? status.replaceAll('_', ' ') : 'not checked';
        row.append(name, value);
        evidence.append(row);
    }
}
function show(report, elapsed) {
    byId('result').textContent = JSON.stringify(report, null, 2);
    const context = report.report?.preview?.balance_chain_context ?? report.chain_context
        ?? (report.simulation ? report.result?.chain_context : null);
    byId('block-context').hidden = !context;
    byId('block-height').textContent = context ? `State at block ${context.height}` : '';
    byId('block-hash').textContent = context?.hash ?? '';
    byId('block-subject').textContent = mode === 'live_testnet_preview' ? 'Confirmed address balance' : 'Result chain state';
    if (mode === 'live_testnet_preview') {
        const preview = report.report?.preview;
        const sent = report.report?.public_query_sent ?? report.public_query_sent;
        byId('sent').textContent = sent === true ? 'Yes' : sent === false ? 'No' : 'Unknown';
        byId('chain').textContent = preview ? `${preview.blocks.toLocaleString()} blocks` : 'Not checked';
        byId('preview-balance').textContent = preview
            ? `${preview.transparent_balance_zatoshis.toLocaleString()} zatoshis` : '—';
        byId('result-label').textContent = report.error || report.report?.query_error ? 'PREVIEW UNAVAILABLE'
            : preview ? 'PUBLIC TESTNET RESULT'
                : report.report && !report.report.public_preview_passed ? 'QUOTE CHECK DID NOT PASS' : 'READY';
        const inspection = report.report?.inspection;
        renderEvidence({
            transport: inspection ? 'managed local Tor' : 'not established',
            hardware: inspection?.hardware_evidence?.hardware_authenticity ?? 'not checked',
            workload: 'unverified',
            channel_binding: inspection?.live_key_binding ?? 'not checked',
            freshness: inspection?.freshness ?? 'not checked',
            release_approval: 'not approved'
        });
    }
    else {
        byId('sent').textContent = report.query_sent === true ? 'Yes' : report.query_sent === false ? 'No' : 'Unknown';
        byId('chain').textContent = String(report.chain_readiness ?? 'not_checked').replaceAll('_', ' ');
        byId('result-label').textContent = mode === 'simulation'
            ? (report.error ? 'SIMULATED REJECTION' : 'SYNTHETIC RESULT')
            : mode === 'phala_trusted_unverified'
                ? (report.phala_trusted_authorized === true && report.query_sent === true && !report.error
                    ? 'PHALA-TRUSTING RESPONSE' : report.phala_trusted_authorized === true ? 'QUERY FAILED' : 'RELEASE NOT APPROVED')
                : (report.private_accepted === true && report.query_sent === true && !report.error
                    ? 'VERIFIED RESPONSE' : report.private_accepted === true ? 'QUERY FAILED' : 'PRIVATE MODE BLOCKED');
        renderEvidence(report.verification);
    }
    byId('latency').textContent = `${elapsed.toFixed(1)} ms`;
}
function updateMethodFields() {
    const method = methodSelect.value;
    const live = mode === 'live_unverified' || mode === 'phala_trusted_unverified';
    byId('live-params').hidden = !live;
    if (mode === 'phala_trusted_unverified') {
        byId('preview-fixture').hidden = method !== 'getaddressbalance';
    }
    byId('height-param').hidden = !live || method !== 'getblockhash';
    byId('hash-param').hidden = !live || !['getblockheader', 'getrawtransaction'].includes(method);
    byId('verbosity-param').hidden = !live || !['getblockheader', 'getrawtransaction'].includes(method);
    byId('hash-label').textContent = method === 'getrawtransaction' ? 'Transaction ID' : 'Block hash';
}
function requestForMethod() {
    const method = methodSelect.value;
    let params = [];
    if (mode === 'simulation') {
        params = method === 'getblockhash' ? [42]
            : ['getblockheader', 'getrawtransaction'].includes(method)
                ? [method === 'getrawtransaction' ? 'b'.repeat(64) : 'a'.repeat(64), true] : [];
    }
    else if (method === 'getblockhash') {
        const raw = byId('height').value;
        const height = Number(raw);
        // The typed protocol permits u32, but the pinned Zebra node adapter accepts i32.
        if (!/^(0|[1-9][0-9]*)$/.test(raw) || !Number.isInteger(height) || height > 0x7fffffff) {
            throw new Error('Enter a whole block height from 0 through 2147483647.');
        }
        params = [height];
    }
    else if (method === 'getaddressbalance' && mode === 'phala_trusted_unverified') {
        const address = byId('preview-address').value.trim();
        if (!address)
            throw new Error('Enter a Zcash testnet transparent address.');
        params = [{ addresses: [address] }];
    }
    else if (method === 'getblockheader' || method === 'getrawtransaction') {
        const hash = byId('hash').value.trim();
        if (!/^[a-fA-F0-9]{64}$/.test(hash)) {
            throw new Error('Enter a 64-digit hexadecimal block hash or transaction ID.');
        }
        const verbosity = byId('verbosity').value;
        if (verbosity !== 'true' && verbosity !== 'false') {
            throw new Error('Choose a supported response detail.');
        }
        params = [hash, verbosity === 'true'];
    }
    return JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
}
methodSelect.addEventListener('change', () => {
    if (mode === 'live_unverified' || mode === 'phala_trusted_unverified') {
        byId('height').value = '';
        byId('hash').value = '';
    }
    updateMethodFields();
});
run.addEventListener('click', async () => {
    run.disabled = true;
    byId('block-context').hidden = true;
    byId('block-height').textContent = '';
    byId('block-hash').textContent = '';
    const started = performance.now();
    try {
        const report = mode === 'live_testnet_preview'
            ? await api(`/api/preview?address=${encodeURIComponent(byId('preview-address').value.trim())}`)
            : await api('/api/query', requestForMethod(), mode === 'simulation' ? byId('scenario').value : undefined);
        show(report, performance.now() - started);
        session.textContent = mode === 'simulation' ? 'Local session ready. Simulation fixtures stay on this device.'
            : mode === 'live_testnet_preview' ? report.report?.preview
                ? 'Public testnet reads completed. Workload identity and private approval remain unverified.'
                : 'Preview stopped before public testnet results were available.'
                : mode === 'phala_trusted_unverified'
                    ? 'Phala-trusting release approval is required before a request is sent.'
                    : 'Local session ready. Private mode requires independent verification.';
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
            throw new Error('Open this dashboard from the zrpc CLI to establish a local session.');
        capability = bootstrap;
        const result = await api('/api/bootstrap');
        capability = result.capability;
        mode = result.mode;
        bootstrap = '';
        if (mode === 'live_testnet_preview') {
            document.querySelector('.notice')?.classList.add('preview');
            byId('mode-label').textContent = 'LIVE TESTNET PREVIEW';
            byId('mode-description').textContent = 'The native client checks a live Intel TDX quote, current collateral, a fresh challenge, and the TLS key before public testnet reads on the retained Tor connection. Workload identity and private approval remain unverified.';
            byId('method-label').hidden = true;
            methodSelect.hidden = true;
            byId('scenario-label').hidden = true;
            byId('scenario').hidden = true;
            byId('preview-fixture').hidden = false;
            byId('sent').previousElementSibling.textContent = 'Public reads sent';
            byId('chain').previousElementSibling.textContent = 'Reported chain height';
            run.firstChild.textContent = 'Run live testnet preview ';
            byId('release-note').textContent = 'Live TDX quote check · Workload identity unverified · No approved private release';
            byId('gate-note').textContent = 'This public preview verifies hardware and the live connection key, not the deployed workload. Only a validated testnet transparent address is sent after the quote check passes.';
            const started = performance.now();
            const status = await api('/api/status');
            if (status.mode !== 'live_testnet_preview' || status.private_accepted !== false ||
                status.query_sent !== false || status.public_query_sent !== false) {
                throw new Error('Local client status is inconsistent. Restart the dashboard from the CLI.');
            }
            if (status.default_address)
                byId('preview-address').value = status.default_address;
            show(status, performance.now() - started);
            session.textContent = 'Ready. Check the live TDX quote and read public testnet data.';
        }
        else if (mode === 'live_unverified' || mode === 'phala_trusted_unverified') {
            const trusted = mode === 'phala_trusted_unverified';
            byId('mode-label').textContent = trusted ? 'PHALA-TRUSTING · UNVERIFIED' : 'LIVE CLIENT · UNVERIFIED';
            byId('mode-description').textContent = trusted
                ? 'This profile trusts Phala with guest administration, KMS and persistent runtime state. The native client still requires a reviewed workload, live TDX quote, fresh TLS key binding and Tor before sending a query. It does not protect against Phala administrators.'
                : 'This dashboard can ask the native client to verify a remote endpoint. No private query is sent unless the independently reviewed release and live connection pass every check.';
            byId('method-label').textContent = 'Typed testnet request';
            byId('scenario-label').style.display = 'none';
            byId('scenario').style.display = 'none';
            for (const option of Array.from(methodSelect.options)) {
                if (option.value === 'getblockhash')
                    option.textContent = 'Block identity by height';
                if (option.value === 'getblockheader')
                    option.textContent = 'Block header by hash';
                if (option.value === 'getrawtransaction')
                    option.textContent = 'Transaction by ID';
            }
            if (trusted) {
                const addressOption = document.createElement('option');
                addressOption.value = 'getaddressbalance';
                addressOption.textContent = 'Testnet transparent address balance';
                methodSelect.append(addressOption);
                byId('preview-note').textContent = 'Only a valid testnet transparent P2PKH or P2SH address is accepted by the native client. Phala is trusted under this profile.';
            }
            updateMethodFields();
            run.firstChild.textContent = 'Try verified query ';
            byId('release-note').textContent = trusted
                ? 'Phala-trusting profile: no reviewed live release is packaged yet. Queries remain blocked.'
                : `${result.platform === 'gcp-tdx' ? 'Google Cloud TDX' : 'Phala dstack'}: no approved production release is packaged yet. Private mode stays blocked.`;
            byId('gate-note').textContent = trusted
                ? 'This qualified claim depends on Phala-operated guest, KMS and runtime controls. The local Rust client must approve the exact release and connection before reading your query.'
                : result.platform === 'gcp-tdx'
                    ? 'Google Cloud TDX boot integrity, administrative isolation, durable storage isolation, channel binding, and external cleanup still need independent validation.'
                    : 'Phala Gates A–E still need genuine evidence.';
            const started = performance.now();
            const status = await api('/api/status');
            if (status.mode !== mode || status.platform !== result.platform ||
                status.private_accepted !== false || status.query_sent !== false) {
                throw new Error('Local client status is inconsistent. Restart the dashboard from the CLI.');
            }
            show(status, performance.now() - started);
            session.textContent = trusted
                ? 'Local session ready. A reviewed Phala-trusting release is required.'
                : 'Local session ready. Private mode requires independent verification.';
            if (trusted) {
                const asideTitle = document.querySelector('.aside strong');
                if (asideTitle)
                    asideTitle.textContent = 'Phala-trusting mode is closed.';
            }
        }
        else if (mode === 'simulation') {
            updateMethodFields();
            byId('mode-label').textContent = 'SIMULATION ONLY';
            byId('mode-description').textContent = 'No hardware attestation, Tor connection, cloud service or live blockchain. Fixtures never authorize private mode.';
            session.textContent = 'Local session ready. Simulation fixtures stay on this device.';
        }
        else {
            throw new Error('Unknown dashboard mode. Restart the dashboard from the CLI.');
        }
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
