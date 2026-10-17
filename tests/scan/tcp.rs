use super::banner_result;

#[test]
fn ssh_banner_preserves_bytes_separately_from_stop_reason() {
    let data = b"SSH-2.0-OpenSSH_10.0\r\n";
    let (service, detail, banner) = banner_result(data, "");
    assert_eq!(service.as_deref(), Some("ssh"));
    assert_eq!(detail, "");
    assert_eq!(banner.as_deref(), Some(data.as_slice()));
}

#[test]
fn received_bytes_do_not_discard_read_timeout() {
    let data = b"partial banner";
    let (_, detail, banner) = banner_result(data, "read timed out");
    assert_eq!(detail, "read timed out");
    assert_eq!(banner.as_deref(), Some(data.as_slice()));
}
