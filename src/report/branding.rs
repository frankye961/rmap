//! Startup identity and version, independent of scan orchestration.

const BANNER: &str = r#"
      \       /
   ___ \_____/ ___
  /   \(o   o)/   \
  \___/  ___  \___/
      \ (___) /
     __\_____/__
    / /       \ \
   (_/         \_)

  RRRRR   M   M    AAA    PPPPP
  R    R  MM MM   A   A   P    P
  R    R  M M M  AAAAAAA  P    P
  RRRRR   M   M  A     A  PPPPP
  R   R   M   M  A     A  P
  R    R  M   M  A     A  P
"#;

pub fn print_banner() {
    println!(
        "{BANNER}\n  v{} - Rust network scanner with optional AI interpretation.\n",
        env!("CARGO_PKG_VERSION")
    );
}
