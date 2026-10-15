use super::file_setting;

#[test]
fn reads_last_matching_setting_without_comments() {
    let sample = "# RUST_NMAP_AI_MODEL=ignored\nRUST_NMAP_AI_MODEL=old\nRUST_NMAP_AI_MODEL=\"sample-model\"\n";
    assert_eq!(
        file_setting(sample, "RUST_NMAP_AI_MODEL").as_deref(),
        Some("sample-model")
    );
}
