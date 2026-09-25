# Operator budget and spending authority

Updated 2026-09-25 from the operator's explicit instructions: $50 was added as credits for the whole deployment; do not spend or use money without asking first. Treat **$50 as the total experiment ceiling**, superseding the source design's approximately $60 envelope. Additional pre-existing or granted account credits do not enlarge this experiment's budget.

Account inspection is authorized. Creating, starting, resizing or otherwise using a billable resource still requires explicit operator approval of a concrete plan. Funding the account is not deployment authorization. All earlier attestation, external deletion and deadline prerequisites remain in force.

The existing $50 preflight ceiling, $45 deletion trigger and 168-hour maximum remain. The modeled detection/deletion delay and fee allowance must now fit the $5 difference between trigger and total cap. No new polling interval or cost trigger was invented. Actual available balance and shared-account consumption must be checked again before a deployment approval request.

At the original published-rate fixture, compute and disk cost $0.24312/hour, $5.83488/day and $40.84416 for 168 hours. This leaves $9.15584 before the total cap, or $4.15584 before the deletion trigger, before any extra costs. The fixture remains synthetic. Current authenticated UI observations are recorded separately in `phala-account-preflight.md` and are not silently substituted for a complete provider quote.

## Implementation and proof

`TOTAL_CEILING_MICROUSD` is now 50,000,000. Planning's reported remaining budget and the existing deletion-delay/fee check use the reduced cap. The regression accepts exactly $45 + $0.24312 modeled delay + $4.75688 fees = $50, then rejects one additional microdollar even though that scenario passes the separate projected-usage gate. The all-cost-categories test retains coverage with fee inputs that fit the new reserve.

Managed-container verification passed: formatting; all **11 lifecycle tests**; CLI build; CLI contract checks including disabled deployment; and the user-docs boundary scanner. Browser/UI implementation was unchanged, so its previously completed visual checks were not repeated. No cloud resources were created, started, changed or deleted by this work; no billing settings were changed.
