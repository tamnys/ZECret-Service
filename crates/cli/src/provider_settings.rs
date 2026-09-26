//! Explicit operator-supplied provider credentials, trust, and resource bounds.

use super::{required, take_value};
use std::{num::NonZeroUsize, path::PathBuf, time::Duration};

pub(super) struct ProviderSettings {
    pub(super) original_binding: PathBuf,
    pub(super) api_key_file: PathBuf,
    pub(super) trust_root_der_files: Vec<PathBuf>,
    pub(super) invocation_budget: Duration,
    pub(super) max_response_bytes: NonZeroUsize,
    pub(super) max_input_file_bytes: NonZeroUsize,
}

pub(super) fn positive_usize(args: &mut Vec<String>, flag: &str) -> Result<NonZeroUsize, String> {
    required(args, flag)?
        .parse::<NonZeroUsize>()
        .map_err(|_| "option requires a positive representable integer".to_owned())
}

impl ProviderSettings {
    /// Parse shared required options, leaving command-specific options to the caller.
    pub(super) fn parse(args: &mut Vec<String>) -> Result<Self, String> {
        let original_binding = PathBuf::from(required(args, "--original-binding")?);
        let api_key_file = PathBuf::from(required(args, "--api-key-file")?);
        let mut trust_root_der_files = Vec::new();
        while let Some(path) = take_value(args, "--trust-root")? {
            trust_root_der_files.push(PathBuf::from(path));
        }
        if trust_root_der_files.is_empty() {
            return Err("required option: --trust-root".to_owned());
        }
        let invocation_budget_ms = required(args, "--invocation-budget-ms")?
            .parse::<u64>()
            .map_err(|_| "option requires a positive representable integer".to_owned())?;
        if invocation_budget_ms == 0 {
            return Err("option requires a positive representable integer".to_owned());
        }
        let max_response_bytes = positive_usize(args, "--max-response-bytes")?;
        let max_input_file_bytes = positive_usize(args, "--max-input-file-bytes")?;
        if !original_binding.is_absolute()
            || !api_key_file.is_absolute()
            || trust_root_der_files.iter().any(|path| !path.is_absolute())
        {
            return Err("provider operations require absolute input file paths".to_owned());
        }
        Ok(Self {
            original_binding,
            api_key_file,
            trust_root_der_files,
            invocation_budget: Duration::from_millis(invocation_budget_ms),
            max_response_bytes,
            max_input_file_bytes,
        })
    }

    #[cfg(unix)]
    pub(super) fn load(
        self,
        workspace_id: &str,
    ) -> Result<zrpc_lifecycle::provider_http::ProviderClient, String> {
        zrpc_lifecycle::provider_inputs::ProviderFiles {
            workspace_id: workspace_id.to_owned(),
            api_key_file: self.api_key_file,
            trust_root_der_files: self.trust_root_der_files,
            max_input_file_bytes: self.max_input_file_bytes,
            invocation_budget: self.invocation_budget,
            max_response_bytes: self.max_response_bytes,
        }
        .load()
        .map_err(|error| error.to_string())
    }
}
