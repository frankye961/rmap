use super::banner_result;

#[test]
fn ssh_banner_sets_service_without_byte_count() {
    let (service, detail) = banner_result(b"SSH-2.0-OpenSSH_10.0\r\n", "");
    assert_eq!(service.as_deref(), Some("ssh"));
    assert_eq!(detail, "SSH-2.0-OpenSSH_10.0");
}
