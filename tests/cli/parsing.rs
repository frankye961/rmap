use super::{CliConfig, parse_cli};
use crate::model::ScanMode;

fn arguments(mode: &[&str]) -> Vec<String> {
    [
        "--target",
        "127.0.0.1",
        "--ports",
        "22,80",
        "--timeout-ms",
        "1000",
    ]
    .into_iter()
    .chain(mode.iter().copied())
    .map(String::from)
    .collect()
}

#[test]
fn selects_each_transport() {
    for (flag, expected) in [("--tcp", ScanMode::Tcp), ("--udp", ScanMode::Udp)] {
        let CliConfig {
            target,
            ports,
            timeout,
            mode,
            use_ai: ai,
            ..
        } = parse_cli(&arguments(&[flag])).unwrap();
        assert_eq!(mode, expected);
        assert_eq!(target, "127.0.0.1");
        assert_eq!(ports, ["22", "80"]);
        assert_eq!(timeout.as_millis(), 1000);
        assert!(!ai);
    }
}

#[test]
fn rejects_conflicting_or_repeated_modes() {
    for flags in [
        vec!["--tcp", "--udp"],
        vec!["--udp", "--tcp"],
        vec!["--tcp", "--tcp"],
        vec!["--udp", "--udp"],
    ] {
        assert!(parse_cli(&arguments(&flags)).is_err());
    }
}

#[test]
fn omitted_ports_selects_the_complete_range_for_both_transports() {
    for flag in ["--tcp", "--udp"] {
        let args: Vec<String> = [flag, "--target", "127.0.0.1", "--timeout-ms", "1000"]
            .into_iter()
            .map(String::from)
            .collect();
        let CliConfig {
            ports, full_scan, ..
        } = parse_cli(&args).unwrap();
        assert!(full_scan);
        assert_eq!(ports.len(), 65_535);
        for (expected, actual) in (1..=u16::MAX).zip(&ports) {
            assert_eq!(*actual, expected.to_string());
        }
    }
}

#[test]
fn explicit_empty_or_invalid_ports_do_not_select_all_ports() {
    for value in ["", "0", "65536", "22,", "null"] {
        let mut args = arguments(&["--tcp"]);
        let index = args.iter().position(|arg| arg == "--ports").unwrap();
        args[index + 1] = value.into();
        assert!(
            parse_cli(&args).is_err(),
            "accepted invalid ports: {value:?}"
        );
    }
}

#[test]
fn ports_flag_still_requires_a_value() {
    let args: Vec<String> = [
        "--tcp",
        "--target",
        "127.0.0.1",
        "--timeout-ms",
        "1000",
        "--ports",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert!(
        parse_cli(&args)
            .unwrap_err()
            .contains("Missing value for --ports")
    );
}

#[test]
fn target_alone_uses_tcp_all_ports_and_one_second_timeout() {
    let args = vec!["--target".into(), "127.0.0.1".into()];
    let CliConfig {
        target,
        ports,
        timeout,
        mode,
        use_ai: ai,
        ..
    } = parse_cli(&args).unwrap();
    assert_eq!(target, "127.0.0.1");
    assert_eq!(mode, ScanMode::Tcp);
    assert_eq!(timeout.as_millis(), 1000);
    assert_eq!(ports.len(), 65_535);
    assert_eq!(ports.first().map(String::as_str), Some("1"));
    assert_eq!(ports.last().map(String::as_str), Some("65535"));
    assert!(!ai);
}

#[test]
fn explicit_options_override_defaults_independently() {
    for (extra, expected_mode, expected_timeout) in [
        (vec!["--udp"], ScanMode::Udp, 1000),
        (vec!["--timeout-ms", "250"], ScanMode::Tcp, 250),
        (vec!["--udp", "--timeout-ms", "250"], ScanMode::Udp, 250),
    ] {
        let args: Vec<String> = ["--target", "127.0.0.1", "--ports", "80,22"]
            .into_iter()
            .chain(extra)
            .map(String::from)
            .collect();
        let CliConfig {
            ports,
            timeout,
            mode,
            ..
        } = parse_cli(&args).unwrap();
        assert_eq!(ports, ["80", "22"]);
        assert_eq!(mode, expected_mode);
        assert_eq!(timeout.as_millis(), expected_timeout);
    }
}

#[test]
fn invalid_or_missing_explicit_timeout_does_not_use_default() {
    for value in ["", "0", "-1", "null", "abc"] {
        let args: Vec<String> = ["--target", "127.0.0.1", "--timeout-ms", value]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(
            parse_cli(&args).is_err(),
            "accepted invalid timeout: {value:?}"
        );
    }
    let args = vec!["--target".into(), "127.0.0.1".into(), "--timeout-ms".into()];
    assert!(
        parse_cli(&args)
            .unwrap_err()
            .contains("Missing value for --timeout-ms")
    );
    assert!(parse_cli(&[]).unwrap_err().contains("Missing --target"));
}

#[test]
fn concurrency_defaults_to_256_and_can_be_overridden() {
    let args = arguments(&[]);
    let CliConfig { concurrency, .. } = parse_cli(&args).unwrap();
    assert_eq!(concurrency, 256);
    for value in [1, 64, 1024] {
        let mut args = arguments(&["--udp"]);
        args.extend(["--concurrency".into(), value.to_string()]);
        assert_eq!(parse_cli(&args).unwrap().concurrency, value);
    }
}

#[test]
fn rejects_invalid_missing_or_repeated_concurrency() {
    for value in ["", "0", "-1", "1025", "abc"] {
        let mut args = arguments(&[]);
        args.extend(["--concurrency".into(), value.into()]);
        assert!(parse_cli(&args).is_err());
    }
    let mut args = arguments(&[]);
    args.push("--concurrency".into());
    assert!(parse_cli(&args).is_err());
    args.extend(["2".into(), "--concurrency".into(), "4".into()]);
    assert!(parse_cli(&args).is_err());
}

#[test]
fn explicit_port_lists_keep_the_complete_report_for_both_transports() {
    for mode in ["--tcp", "--udp"] {
        assert!(!parse_cli(&arguments(&[mode])).unwrap().full_scan);
    }
}
