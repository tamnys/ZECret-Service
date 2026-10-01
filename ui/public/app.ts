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

const paymentBalance = getElement<HTMLElement>('payment-balance');
const paymentStep = getElement<HTMLElement>('payment-step');
const paymentNext = getElement<HTMLButtonElement>('payment-next');
const paymentExample = [
  {
    balance: '0',
    text: 'The native client prepares two blinded requests. This browser creates no real tickets.',
    next: 'Simulate issuance'
  },
  {
    balance: '2',
    text: 'The operator simulates settlement. The issuer signs both requests, and the client stores two verified tickets locally. No ZEC is paid.',
    next: 'Spend one credit'
  },
  {
    balance: '1',
    text: 'After verifying Tor and the service connection, the client sends one ticket. The service admits the query and records that ticket as spent.',
    next: 'Try the same ticket again'
  },
  {
    balance: '1',
    text: 'The spent ticket cannot be used again. The remaining credit stays available in this example.',
    next: 'Start again'
  }
] as const;
let paymentStage = -1;

paymentNext.addEventListener('click', () => {
  paymentStage = paymentStage === paymentExample.length - 1 ? -1 : paymentStage + 1;
  if (paymentStage === -1) {
    paymentBalance.textContent = '0';
    paymentStep.textContent = 'Walk through a two-credit example. Nothing is purchased or stored.';
    paymentNext.textContent = 'Prepare two credits';
    return;
  }
  const stage = paymentExample[paymentStage];
  paymentBalance.textContent = stage.balance;
  paymentStep.textContent = stage.text;
  paymentNext.textContent = stage.next;
});
