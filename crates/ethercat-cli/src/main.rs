mod cli;
mod commands;
mod selector;
#[cfg(test)]
mod tests;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, OutputFormat};
use crate::commands::{execute_cli, CommandRender};
use crate::selector::{apply_field_selectors, format_selected_fields_text};
use ethercat_wire::error::{CliError, ErrorEnvelope, Result, EXIT_OK, EXIT_USAGE};

fn parse_format_value(v: &str) -> Option<OutputFormat> {
    if v.eq_ignore_ascii_case("json") {
        Some(OutputFormat::Json)
    } else if v.eq_ignore_ascii_case("json-compact") {
        Some(OutputFormat::JsonCompact)
    } else {
        None
    }
}

fn detect_json_flag_from_raw_args() -> Option<OutputFormat> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut found: Option<OutputFormat> = None;
    let mut idx = 0usize;
    while idx < args.len() {
        let a = &args[idx];
        if a == "--" {
            break;
        }
        if let Some(rest) = a
            .strip_prefix("--format=")
            .or_else(|| a.strip_prefix("-o="))
        {
            found = parse_format_value(rest);
        } else if a == "--format" || a == "-o" {
            if let Some(next) = args.get(idx + 1) {
                found = parse_format_value(next);
            }
            idx += 1;
        } else if let Some(rest) = a.strip_prefix("-o") {
            if !rest.starts_with('-') && !rest.is_empty() {
                found = parse_format_value(rest);
            }
        }
        idx += 1;
    }
    found
}

fn main() -> ExitCode {
    let raw_fmt_hint = detect_json_flag_from_raw_args();

    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                let _ = e.print();
                return ExitCode::from(EXIT_OK as u8);
            }
            let usage_err = CliError::Usage(e.to_string().trim().to_string());
            if let Some(fmt) = raw_fmt_hint {
                emit_error(&usage_err, fmt);
            } else {
                let _ = e.print();
            }
            return ExitCode::from(EXIT_USAGE as u8);
        }
    };

    let fmt = cli.format;
    match execute_cli(&cli) {
        Ok(render) => match finalize_output(render, &cli.fields, fmt) {
            Ok(()) => ExitCode::from(EXIT_OK as u8),
            Err(err) => {
                emit_error(&err, fmt);
                ExitCode::from(err.exit_code() as u8)
            }
        },
        Err(err) => {
            emit_error(&err, fmt);
            ExitCode::from(err.exit_code() as u8)
        }
    }
}

fn finalize_output(render: CommandRender, fields: &[String], fmt: OutputFormat) -> Result<()> {
    if !fields.is_empty() {
        let selected = apply_field_selectors(&render.json, fields)?;
        match fmt {
            OutputFormat::Text => println!("{}", format_selected_fields_text(&selected, fields)),
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&selected).unwrap_or_default()
                );
            }
            OutputFormat::JsonCompact => {
                println!("{}", serde_json::to_string(&selected).unwrap_or_default());
            }
        }
        return Ok(());
    }

    match fmt {
        OutputFormat::Text => println!("{}", render.text.trim_end()),
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&render.json).unwrap_or_default()
            );
        }
        OutputFormat::JsonCompact => {
            println!(
                "{}",
                serde_json::to_string(&render.json).unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn emit_error(err: &CliError, fmt: OutputFormat) {
    let env = ErrorEnvelope::from(err);
    match fmt {
        OutputFormat::Text => eprintln!("ERROR [exit={}]: {}", env.exit_code, err),
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&env).unwrap_or_else(|_| "{}".into())
            );
        }
        OutputFormat::JsonCompact => {
            println!(
                "{}",
                serde_json::to_string(&env).unwrap_or_else(|_| "{}".into())
            );
        }
    }
}
