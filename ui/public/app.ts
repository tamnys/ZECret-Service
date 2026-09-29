type SiteStatus = {
  kind: string;
  as_of: string;
  release_approval: { state: string; detail: string };
  transport_attestation: { state: string; detail: string };
  payment: { state: string; detail: string };
  chain_data: { state: string; detail: string };
};

type Scenario = {
  kind: 'synthetic_fixture' | 'payment_simulation';
  title: string;
  explanation: string;
  simulated_decision: string;
  real_private_query_sent: false;
  reason?: string;
  chain_data: { kind: string; method: string; block_height: number } | null;
};

const statusIds = [
  ['release_approval', 'status-release'],
  ['transport_attestation', 'status-transport'],
  ['payment', 'status-payment'],
  ['chain_data', 'status-chain']
] as const;

function getElement<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error('The public page is incomplete.');
  return node as T;
}

async function getJson(path: string): Promise<unknown> {
  const response = await fetch(path, {
    method: 'GET',
    mode: 'same-origin',
    credentials: 'omit',
    redirect: 'error',
    cache: 'no-store'
  });
  if (!response.ok) throw new Error('Public example unavailable.');
  return response.json();
}

function statusValue(value: { state: string; detail: string }, id: string): void {
  const node = getElement(id);
  node.textContent = `${value.state.replaceAll('_', ' ')} · ${value.detail}`;
  node.dataset.state = value.state;
}

async function loadStatus(): Promise<void> {
  try {
    const value = await getJson('/api/status') as SiteStatus;
    if (value.kind !== 'repository_snapshot' || !/^\d{4}-\d{2}-\d{2}$/.test(value.as_of)) {
      throw new Error('Status source unavailable.');
    }
    for (const [key, id] of statusIds) statusValue(value[key], id);
    getElement('status-source').textContent = `Repository snapshot · ${value.as_of}. No live deployment check.`;
  } catch {
    for (const [, id] of statusIds) statusValue({ state: 'unavailable', detail: 'Status could not be loaded.' }, id);
    getElement('status-source').textContent = 'Public status unavailable. No live deployment check.';
  }
}

const scenarioSelect = getElement<HTMLSelectElement>('scenario');
const runButton = getElement<HTMLButtonElement>('run-scenario');
const result = getElement<HTMLElement>('scenario-result');
const resultTitle = getElement<HTMLElement>('scenario-title');
const resultNote = getElement<HTMLElement>('scenario-note');

runButton.addEventListener('click', async () => {
  const selected = scenarioSelect.value;
  if (!['success', 'release-rejected', 'ticket-replay'].includes(selected)) return;
  runButton.disabled = true;
  resultTitle.textContent = 'Loading fixture…';
  resultNote.textContent = 'The site requests only a fixed example from its own public Worker.';
  result.textContent = '';
  try {
    const example = await getJson(`/api/scenarios/${selected}`) as Scenario;
    if (!['synthetic_fixture', 'payment_simulation'].includes(example.kind) || example.real_private_query_sent !== false) {
      throw new Error('Invalid fixture response.');
    }
    resultTitle.textContent = `${example.title} · ${example.kind.replaceAll('_', ' ')}`;
    resultNote.textContent = example.explanation;
    result.textContent = JSON.stringify(example, null, 2);
  } catch {
    resultTitle.textContent = 'Example unavailable';
    resultNote.textContent = 'The public fixture could not be loaded. No native query was attempted.';
    result.textContent = '';
  } finally {
    runButton.disabled = false;
  }
});

void loadStatus();
