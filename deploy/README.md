# Deployment boundary

The repository includes cost/manifest fixtures and native lifecycle commands. Local ledger setup/inspection, authenticated provider observations and explicit tracked deletion are available. There is no resource-creation path, enabled Compose deployment or activated scheduler. `zrpc deploy` refuses unconditionally.

Do not turn placeholders into cloud resources. Pin the production images and resolve the hardware/workload, live-key, administration, KMS/disk and resource gates first. A working external deletion/deadline mechanism and a separate explicit operator deployment action are required before starting a billable experiment. See the operator runbook.
