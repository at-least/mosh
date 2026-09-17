//! The SSH bootstrap (spec §1): exec `mosh-server new` over the russh
//! session, parse `MOSH SSH_CONNECTION` (the UDP target on multihomed
//! servers) and `MOSH CONNECT <port> <key>` out of the merged output.
//! The parser is pure (monitor.rs precedent); the command string
//! mirrors mosh.pl's construction, including its shell quoting.

use thiserror::Error;

/// Everything the client needs after a successful bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoshBootstrap {
    /// The server-side IP from `$SSH_CONNECTION` (word 4 of the probe
    /// line) — the UDP target. `None` if the server never printed the
    /// probe; callers fall back to the SSH hostname.
    pub server_ip: Option<String>,
    /// The UDP port mosh-server bound.
    pub port: u16,
    /// The 22-character session key (still printable form).
    pub key: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MoshBootstrapError {
    /// Channel closed with no `MOSH CONNECT` line. `output` carries the
    /// tail of what WAS said (mosh-server errors go to stderr, e.g. the
    /// UTF-8-locale refusal or "command not found").
    #[error("no MOSH CONNECT line (is mosh ≥ 1.4 installed on the server?): {output}")]
    NoConnect { output: String },
    #[error("bad MOSH CONNECT line: {0}")]
    BadConnect(String),
    #[error("bad MOSH SSH_CONNECTION line: {0}")]
    BadConnection(String),
}

/// The `mosh-server new` command exactly as mosh.pl builds it (spec §1):
/// the `$SSH_CONNECTION` probe first, then `new -c 256 -s -l <locale>`
/// and the optional payload after `--`. Args are shell-quoted with
/// mosh.pl's rule (wrap in single quotes, `'` becomes `'\''`).
/// The tmux-attach payload as ARGV for `mosh-server new --` (the
/// SSH-path constant is a whole shell line; mosh takes one argument per
/// word). Both platforms pass this as the payload list.
pub fn mosh_tmux_payload_args() -> Vec<String> {
    [
        "env",
        "COLORTERM=truecolor",
        "tmux",
        "new-session",
        "-A",
        "-s",
        "conch",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn mosh_server_command(
    locale: &str,
    payload: Option<Vec<String>>,
    port: Option<u16>,
) -> String {
    let payload = payload.as_deref();
    mosh_server_command_inner(locale, payload, port)
}

fn mosh_server_command_inner(
    locale: &str,
    payload: Option<&[String]>,
    port: Option<u16>,
) -> String {
    // mosh.pl sends the probe prefix RAW (the remote shell interprets
    // it) and shell-quotes only the mosh-server arguments.
    let probe = "sh -c '[ -n \"$SSH_CONNECTION\" ] && printf \"\\nMOSH SSH_CONNECTION %s\\n\" \"$SSH_CONNECTION\"'";
    let mut quoted = vec![
        "new".to_string(),
        "-c".to_string(),
        "256".to_string(),
        "-s".to_string(),
        "-l".to_string(),
        format!("LANG={locale}"),
    ];
    if let Some(port) = port {
        quoted.push("-p".to_string());
        quoted.push(port.to_string());
    }
    if let Some(payload) = payload {
        quoted.push("--".to_string());
        quoted.extend(payload.iter().cloned());
    }
    let quoted = quoted
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{probe} ; mosh-server {quoted}")
}

/// mosh.pl's shell_quote: every argument wrapped in single quotes with
/// embedded quotes escaped as `'\''`.
fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Parse the merged channel output. `MOSH SSH_CONNECTION` may appear at
/// most once (a redefinition is an error, like mosh.pl); the first
/// well-formed `MOSH CONNECT` wins; everything else is informational.
pub fn parse_mosh_bootstrap(output: &str) -> Result<MoshBootstrap, MoshBootstrapError> {
    let mut server_ip: Option<String> = None;
    let mut bootstrap: Option<MoshBootstrap> = None;
    let mut informational = Vec::new();

    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("MOSH SSH_CONNECTION ") {
            let words: Vec<&str> = rest.split_whitespace().collect();
            // "MOSH SSH_CONNECTION cip cport sip sport" == 6 words total
            if words.len() != 4 {
                return Err(MoshBootstrapError::BadConnection(line.to_string()));
            }
            if server_ip.is_some() {
                return Err(MoshBootstrapError::BadConnection(
                    "attempt to redefine MOSH SSH_CONNECTION".into(),
                ));
            }
            server_ip = Some(words[2].to_string());
        } else if line.starts_with("MOSH CONNECT ") {
            if bootstrap.is_none() {
                let words: Vec<&str> = line.split_whitespace().collect();
                if words.len() != 4 {
                    return Err(MoshBootstrapError::BadConnect(line.to_string()));
                }
                let port: u16 = words[2]
                    .parse()
                    .map_err(|_| MoshBootstrapError::BadConnect(line.to_string()))?;
                let key = words[3];
                if key.len() != 22
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+')
                {
                    return Err(MoshBootstrapError::BadConnect(line.to_string()));
                }
                bootstrap = Some(MoshBootstrap {
                    server_ip: None, // patched below once the scan ends
                    port,
                    key: key.to_string(),
                });
            }
        } else {
            informational.push(line);
        }
    }

    match bootstrap {
        Some(mut parsed) => {
            parsed.server_ip = server_ip;
            Ok(parsed)
        }
        None => {
            // keep the tail of whatever the channel said, stderr first
            let mut output = informational.join("\n");
            if output.chars().count() > 400 {
                // last 400 CHARS (byte slicing could split a multibyte
                // mosh-server error message)
                let tail: String = output.chars().rev().take(400).collect();
                let tail: String = tail.chars().rev().collect();
                output = format!("…{tail}");
            }
            Err(MoshBootstrapError::NoConnect { output })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_mirrors_mosh_pl() {
        let cmd = mosh_server_command("C.UTF-8", None, None);
        assert_eq!(
            cmd,
            "sh -c '[ -n \"$SSH_CONNECTION\" ] && printf \"\\nMOSH SSH_CONNECTION %s\\n\" \"$SSH_CONNECTION\"' ; \
             mosh-server 'new' '-c' '256' '-s' '-l' 'LANG=C.UTF-8'"
        );
        // pinned UDP port rides as '-p <port>' before the payload
        let cmd = mosh_server_command("C.UTF-8", None, Some(60100));
        assert!(cmd.contains("'new' '-c' '256' '-s' '-l' 'LANG=C.UTF-8' '-p' '60100'"));
        // the tmux composition: payload after --
        let payload = vec!["tmux new-session -A -s conch".to_string()];
        let cmd = mosh_server_command("C.UTF-8", Some(payload), None);
        assert!(cmd.ends_with("'--' 'tmux new-session -A -s conch'"));

        // hostile payload characters are quoted mosh.pl-style
        let evil = vec!["it's; rm -rf /".to_string()];
        let cmd = mosh_server_command("C.UTF-8", Some(evil), None);
        assert!(cmd.contains("'\\''"), "single quotes escaped: {cmd}");
        // the whole payload is exactly one quoted argument
        assert!(
            cmd.contains("'it'\\''s; rm -rf /'"),
            "payload stays one argument: {cmd}"
        );
    }

    #[test]
    fn parses_probe_then_connect() {
        let out = "\nMOSH SSH_CONNECTION 192.168.1.5 51234 10.0.0.7 22\n\nMOSH CONNECT 60001 7l1cNvxYVkWP1j8zMC08Jg\n";
        let parsed = parse_mosh_bootstrap(out).unwrap();
        assert_eq!(parsed.server_ip.as_deref(), Some("10.0.0.7"));
        assert_eq!(parsed.port, 60001);
        assert_eq!(parsed.key, "7l1cNvxYVkWP1j8zMC08Jg");
    }

    #[test]
    fn connect_without_probe_falls_back_to_none() {
        let out = "MOSH CONNECT 61000 AAAAAAAAAAAAAAAAAAAAAA\n";
        let parsed = parse_mosh_bootstrap(out).unwrap();
        assert_eq!(parsed.server_ip, None);
        assert_eq!(parsed.port, 61000);
    }

    #[test]
    fn no_connect_surfaces_the_error_tail() {
        let out = "\nmosh-server needs a UTF-8 native locale to run.\n\nTry running...";
        let err = parse_mosh_bootstrap(out).unwrap_err();
        match err {
            MoshBootstrapError::NoConnect { output } => {
                assert!(output.contains("UTF-8 native locale"));
            }
            other => panic!("wrong error: {other}"),
        }
        // and the classic missing-binary case
        let err = parse_mosh_bootstrap("bash: mosh-server: command not found\n").unwrap_err();
        assert!(err.to_string().contains("command not found"));
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert!(matches!(
            parse_mosh_bootstrap("MOSH CONNECT 61000 short\n"),
            Err(MoshBootstrapError::BadConnect(_))
        ));
        assert!(matches!(
            parse_mosh_bootstrap("MOSH CONNECT 61000 AAAAAAAAAAAAAAAAAAAAAA!"),
            Err(MoshBootstrapError::BadConnect(_))
        ));
        assert!(matches!(
            parse_mosh_bootstrap("MOSH CONNECT notaport AAAAAAAAAAAAAAAAAAAAAA"),
            Err(MoshBootstrapError::BadConnect(_))
        ));
        assert!(matches!(
            parse_mosh_bootstrap("MOSH SSH_CONNECTION a b\nMOSH CONNECT 1 AAAAAAAAAAAAAAAAAAAAAA"),
            Err(MoshBootstrapError::BadConnection(_))
        ));
        assert!(matches!(
            parse_mosh_bootstrap(
                "MOSH SSH_CONNECTION a b c d\nMOSH SSH_CONNECTION e f g h\nMOSH CONNECT 1 AAAAAAAAAAAAAAAAAAAAAA"
            ),
            Err(MoshBootstrapError::BadConnection(_))
        ));
    }

    #[test]
    fn first_connect_wins_and_banner_is_informational() {
        let out = "MOSH CONNECT 60001 AAAAAAAAAAAAAAAAAAAAAA\n\
                   [mosh-server detached, pid = 1234]\n\
                   mosh-server (mosh 1.4.0) [build mosh 1.4.0]\n";
        let parsed = parse_mosh_bootstrap(out).unwrap();
        assert_eq!(parsed.port, 60001);
        assert_eq!(parsed.key, "AAAAAAAAAAAAAAAAAAAAAA");
    }
}
