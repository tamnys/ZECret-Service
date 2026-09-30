type Scenario = {
  kind: 'synthetic_fixture' | 'payment_simulation';
  title: string;
  explanation: string;
  simulated_decision: string;
  real_private_query_sent: false;
  reason?: string;
  chain_data: { kind: string; method: string; block_height: number } | null;
};

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
