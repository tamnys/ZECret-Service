//! Literal arguments for a single systemd ExecStart directive, without a shell.

use crate::LifecycleError;

/// Encode one executable and its arguments. The caller validates the selected
/// executable path; this function also excludes executable prefixes and syntax
/// that systemd cannot preserve as a literal executable path.
///
/// Versioned upstream syntax and implementation references:
/// - https://github.com/systemd/systemd/blob/v257/man/systemd.syntax.xml
/// - https://github.com/systemd/systemd/blob/v257/man/systemd.service.xml
/// - https://github.com/systemd/systemd/blob/v257/src/core/load-fragment.c
/// - https://github.com/systemd/systemd/blob/v257/src/core/exec-invoke.c
/// - https://github.com/systemd/systemd/blob/v257/src/basic/string-util.c
///
/// Whole-token double quotes and C escapes preserve argument boundaries. `%%`
/// escapes specifiers, and `$$` prevents environment expansion in arguments.
/// systemd resolves the executable separately, before argv environment expansion:
/// doubling a dollar there would select a different executable. Reject it rather
/// than silently changing the path. systemd's executable `string_is_safe` check
/// also rejects quotes and backslashes after unquoting.
pub(super) fn exec_command(arguments: &[String]) -> Result<String, LifecycleError> {
    let executable = arguments
        .first()
        .ok_or(LifecycleError("systemd command requires an executable"))?;
    if !executable.starts_with('/') || executable.contains(['$', '\\', '\'', '"']) {
        return Err(LifecycleError(
            "systemd executable requires an absolute path without dollars, quotes or backslashes",
        ));
    }
    if arguments.iter().any(|argument| {
        argument
            .chars()
            .any(|character| character.is_control() || matches!(character, '\u{2028}' | '\u{2029}'))
    }) {
        return Err(LifecycleError(
            "systemd command arguments cannot contain control characters or line separators",
        ));
    }

    let mut encoded = String::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            encoded.push(' ');
        }
        encoded.push('"');
        for character in argument.chars() {
            match character {
                '\\' => encoded.push_str("\\\\"),
                '"' => encoded.push_str("\\\""),
                '$' => encoded.push_str("$$"),
                '%' => encoded.push_str("%%"),
                _ => encoded.push(character),
            }
        }
        encoded.push('"');
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(arguments: &[&str]) -> Result<String, LifecycleError> {
        exec_command(
            &arguments
                .iter()
                .map(|argument| (*argument).into())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn command_and_each_argument_are_separate_quoted_tokens() {
        assert_eq!(
            encode(&[
                "/opt/zrpc tools/zrpc",
                "lifecycle",
                "watchdog-once",
                "",
                " spaced ",
                "例",
            ])
            .unwrap(),
            "\"/opt/zrpc tools/zrpc\" \"lifecycle\" \"watchdog-once\" \"\" \" spaced \" \"例\""
        );
    }

    #[test]
    fn substitutions_and_c_escapes_remain_literal() {
        assert_eq!(
            encode(&[
                "/opt/%i/zrpc",
                r#"quote" slash\ end\"#,
                "${HOME}",
                "$USER",
                "$$",
                "%n%%",
                r"\n\x41",
            ])
            .unwrap(),
            r#""/opt/%%i/zrpc" "quote\" slash\\ end\\" "$${HOME}" "$$USER" "$$$$" "%%n%%%%" "\\n\\x41""#
        );
    }

    #[test]
    fn quoted_shell_punctuation_cannot_become_another_command() {
        assert_eq!(
            encode(&[
                "/opt/zrpc",
                ";",
                "&&",
                "|",
                ">output",
                "#comment",
                "'",
                "-+/bin/other",
            ])
            .unwrap(),
            "\"/opt/zrpc\" \";\" \"&&\" \"|\" \">output\" \"#comment\" \"'\" \"-+/bin/other\""
        );
    }

    #[test]
    fn empty_relative_prefixed_or_unrepresentable_executable_is_rejected() {
        assert!(exec_command(&[]).is_err());
        for executable in [
            "",
            "zrpc",
            "./zrpc",
            "../zrpc",
            "+/opt/zrpc",
            "!/opt/zrpc",
            "!!/opt/zrpc",
            "@/opt/zrpc",
            ":/opt/zrpc",
            "-/opt/zrpc",
            "|/opt/zrpc",
            "/opt/$USER/zrpc",
            "/opt/$$/zrpc",
            "/opt/quote\"/zrpc",
            "/opt/quote'/zrpc",
            "/opt/slash\\/zrpc",
        ] {
            assert!(encode(&[executable]).is_err(), "{executable:?}");
        }
    }

    #[test]
    fn controls_and_line_separators_are_rejected_in_every_position() {
        for character in (0..=0x1f)
            .chain(0x7f..=0x9f)
            .chain([0x2028, 0x2029])
            .map(|value| char::from_u32(value).unwrap())
        {
            let executable = format!("/opt/{character}/zrpc");
            assert!(encode(&[&executable]).is_err());
            let argument = format!("before{character}after");
            assert!(encode(&["/opt/zrpc", &argument]).is_err());
        }
    }
}
