use super::file_setting;

#[test]
fn reads_last_matching_setting_without_comments() {
    let sample = "# RMAP_AI_MODEL=ignored\nRMAP_AI_MODEL=old\nRMAP_AI_MODEL=\"sample-model\"\n";
    assert_eq!(
        file_setting(sample, "RMAP_AI_MODEL").as_deref(),
        Some("sample-model")
    );
}
