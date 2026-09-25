# Deployment boundary

M0 includes cost/manifest fixtures and native lifecycle commands only. There is no enabled Compose deployment, provider API adapter or scheduler. `zrpc deploy` refuses unconditionally.

Do not turn placeholders into cloud resources. Pin the production images and resolve the hardware/workload, live-key, administration, KMS/disk and resource gates first. A working external deletion/deadline mechanism and a separate explicit operator deployment action are required before starting a billable experiment. See the operator runbook.
