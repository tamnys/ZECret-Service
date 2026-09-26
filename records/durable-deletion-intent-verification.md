# Exact billing and durable cleanup intent — 2026-09-25

Contract: advance the external cleanup prerequisite without creating a provider
client, authorizing cloud operations, accessing credentials or installing jobs.
Preserve exact provider amounts and persist an immutable deletion intent before
exposing it to a future request executor. Retain uncertainty after interruption.

## Implemented boundaries

`amount::ExactUsd` parses nonnegative JSON number tokens without floating point,
normalizes equivalent spellings and retains differences smaller than a
microdollar. Conversion rounds upward to the existing integer microUSD unit with
checked overflow. Exponents use the platform's `i128` representation and never
allocate an exponent-sized zero string. Invalid/negative tokens, including
negative zero, are rejected. The ledger accepts scientific notation, compares
duplicate billing records by exact numeric value, and preserves the originally
stored lexeme. Different charges that round to the same microUSD still conflict.

`provider_wire` decodes projections of the pinned Phala API shape from original
JSON bytes. It preserves distinct CVM and usage identifiers and exact monetary
tokens, rejects duplicate critical fields and unsupported types, and requires an
explicit positive caller-provided body bound. It does not authenticate workspace
scope, join usage to a tracked CVM, establish complete pagination, or interpret
an empty page as settled billing. Source and fixture details are in
`provider-wire-verification.md`.

`LedgerStore::prepare_deletion` checks the actual committed generation, original
workspace, an already tracked canonical CVM, nondecreasing time and unchanged
store history. It durably publishes the intent using the existing file/directory
sync sequence before returning `CommittedDeletionIntent`. That value borrows
the writer store, retains its OS lock, and cannot be cloned or deserialized.
Its record includes the prior and committed generations, full tracked target
identity and intent time. It is a local durability fact, not operator approval,
provider authentication or an available network capability.

The token's consuming `finish` method records one sanitized outcome in a later
snapshot. Dropping the token leaves its committed intent pending. Existing
intent identity and completed outcomes cannot be changed or removed. Generic
`commit` refuses journal changes even from caller-supplied restored JSON;
purpose-specific writes alone may add intent/outcome history. Replay checks the
actual predecessor generation and excludes targets introduced in the same
snapshot. Initial/generation-zero state cannot contain a deletion journal.

Intent remains possible after the original deadline or spending ceiling: those
conditions must not veto cleanup. Original budget, time window, prior attempts,
resources and cumulative costs are retained. No result establishes disappearance
or lowers the cost floor; 204, 404 and transport uncertainty remain incomplete
cleanup. Existing synthetic mock behavior remains separately labeled.

Same-target reconciliation/retry is deliberately not exposed yet. This is an
unfinished capability boundary, not a numerical request quota: the future live
runner must reconcile and obtain explicit invocation authority before another
request. Other previously tracked targets can still receive their own intent.
No recovery API guesses what happened after a lost response or fabricates an
observation. The state is inspectable through its immutable journal.

## Verification

Focused managed-container lifecycle tests passed: 62 unit tests and two
compile-fail documentation tests. Coverage includes exact exponent/rounding
boundaries, malformed/negative charges, duplicate equivalent values versus
different submicroUSD charges, provider object/field/body rules, stale generation,
wrong scope, untracked target, backwards time, persistence-before-token, retained
writer lock, drop/reopen, generic commit forgery, altered journal replay, overdue
cleanup, and all six existing persistence write boundaries for both intent and
outcome failure. The previous abrupt-process-exit storage tests also remain in
the affected suite. No dependency versions or lockfiles changed.

Full `CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed in the
managed untrusted browser-profile Linux container: 164 workspace unit tests,
18 compile-fail documentation tests, 14 runtime-guard tests, the dependency and
fixture guards, CLI/public-inspector/wrapper executable checks, and all required
builds. The four new fixture hashes match their provenance manifest. No UI or
user documentation changed, so visual QA and the user-doc scanner were not
rerun. The container shell was reused for focused and full verification.

## Remaining live requirements

No provider HTTP/TLS transport or credential loader exists, no API call was made,
and no operator CLI was added for deletion. Authentication, response/page timing
and allocation policy, CVM-to-usage identity mapping, crash reconciliation/retry,
periodic/deadline/backstop activation, independent disk disappearance and billing
finality remain unfinished. These local tests cannot close Phala feasibility
gate E or any hardware/privacy gate. No deployment or spending occurred.
