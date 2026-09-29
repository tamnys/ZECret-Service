use std::{env, error::Error, fs, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

use dcap_qvl::collateral::{CollateralClient, PHALA_PCCS_URL};

struct Inputs {
    quote: PathBuf,
    output: PathBuf,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Inputs, &'static str> {
    let mut args = args.into_iter();
    let _program = args.next();
    let mut quote = None;
    let mut output = None;
    let mut fetch_confirmed = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--quote" if quote.is_none() => {
                quote = Some(PathBuf::from(args.next().ok_or("missing quote path")?))
            }
            "--output" if output.is_none() => {
                output = Some(PathBuf::from(args.next().ok_or("missing output path")?));
            }
            "--fetch-from-phala-pccs" if !fetch_confirmed => fetch_confirmed = true,
            _ => return Err("unexpected or duplicate argument"),
        }
    }
    if !fetch_confirmed {
        return Err("explicit --fetch-from-phala-pccs required");
    }
    let quote = quote.ok_or("--quote is required")?;
    let output = output.ok_or("--output is required")?;
    if !quote.is_absolute() || !output.is_absolute() || quote == output {
        return Err("distinct absolute input and output paths required");
    }
    Ok(Inputs { quote, output })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let input = parse_args(env::args()).map_err(|message| {
        format!("{message}; usage: phala-collateral-fetcher --quote ABSOLUTE_QUOTE_BIN --output ABSOLUTE_NEW_JSON --fetch-from-phala-pccs")
    })?;
    let quote = fs::read(&input.quote)?;
    if quote.is_empty() {
        return Err("quote file is empty".into());
    }
    let collateral = CollateralClient::with_default_http(PHALA_PCCS_URL)?
        .fetch(&quote)
        .await?;
    let json = serde_json::to_vec(&collateral)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&input.output)?;
    output.write_all(&json)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    #[test]
    fn explicit_network_operation_and_distinct_paths_are_required() {
        let base = [
            "fetcher",
            "--quote",
            "/workspace/quote.bin",
            "--output",
            "/workspace/collateral.json",
        ];
        assert!(parse_args(base.map(str::to_string)).is_err());
        let selected = base.into_iter().chain(["--fetch-from-phala-pccs"]);
        let inputs = parse_args(selected.map(str::to_string)).expect("explicit request");
        assert_eq!(inputs.quote.to_str(), Some("/workspace/quote.bin"));
        assert_eq!(inputs.output.to_str(), Some("/workspace/collateral.json"));
        assert!(
            parse_args(
                [
                    "fetcher",
                    "--quote",
                    "/workspace/same",
                    "--output",
                    "/workspace/same",
                    "--fetch-from-phala-pccs"
                ]
                .map(str::to_string)
            )
            .is_err()
        );
    }
}
