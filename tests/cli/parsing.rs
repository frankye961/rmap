use super::parse_cli;
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
        let (target, ports, timeout, mode, ai) = parse_cli(&arguments(&[flag])).unwrap();
        assert_eq!(mode, expected);
        assert_eq!(target, "127.0.0.1");
        assert_eq!(ports, ["22", "80"]);
        assert_eq!(timeout.as_millis(), 1000);
        assert!(!ai);
    }
}

#[test]
fn requires_one_unambiguous_mode() {
    for flags in [
        vec![],
        vec!["--tcp", "--udp"],
        vec!["--udp", "--tcp"],
        vec!["--tcp", "--tcp"],
        vec!["--udp", "--udp"],
    ] {
        assert!(parse_cli(&arguments(&flags)).is_err());
    }
}
