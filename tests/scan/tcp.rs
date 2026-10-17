use super::{banner_result, read_banner};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

// In-memory scripted reader; no socket or network calls are needed.
struct ScriptedRead<F>(F);

impl<F> AsyncRead for ScriptedRead<F>
where
    F: FnMut(&mut [u8]) -> io::Result<usize> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let size = (self.0)(buffer.initialize_unfilled())?;
        buffer.advance(size);
        Poll::Ready(Ok(()))
    }
}

#[test]
fn ssh_banner_preserves_bytes_separately_from_stop_reason() {
    let data = b"SSH-2.0-OpenSSH_10.0\r\n";
    let (detail, banner) = banner_result(data, "");
    assert_eq!(detail, "");
    assert_eq!(banner.as_deref(), Some(data.as_slice()));
}

#[test]
fn received_bytes_do_not_discard_read_timeout() {
    let data = b"partial banner";
    let (detail, banner) = banner_result(data, "read timed out");
    assert_eq!(detail, "read timed out");
    assert_eq!(banner.as_deref(), Some(data.as_slice()));
}

#[tokio::test]
async fn collects_banner_across_more_than_eight_short_reads() {
    let data = b"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n";
    let mut offset = 0;
    let (reason, banner) = read_banner(
        ScriptedRead(|buffer: &mut [u8]| {
            if offset == data.len() {
                return Ok(0);
            }
            buffer[0] = data[offset];
            offset += 1;
            Ok(1)
        }),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(reason, "");
    assert_eq!(banner.as_deref(), Some(data.as_slice()));
}

#[tokio::test]
async fn banner_collection_stops_at_byte_limit_even_without_a_newline() {
    let mut read_count = 0;
    let (reason, banner) = read_banner(
        ScriptedRead(|buffer: &mut [u8]| {
            read_count += 1;
            buffer.fill(b'a');
            Ok(buffer.len())
        }),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(read_count, 8);
    assert_eq!(reason, "");
    assert_eq!(banner.unwrap().len(), 512);
}

#[tokio::test]
async fn retries_interrupted_reads_without_losing_partial_banner() {
    let mut call = 0;
    let (_, banner) = read_banner(
        ScriptedRead(|buffer: &mut [u8]| {
            call += 1;
            match call {
                1 => {
                    buffer[0] = b'x';
                    Ok(1)
                }
                2 => Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
                _ => {
                    buffer[0] = b'\n';
                    Ok(1)
                }
            }
        }),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(banner.as_deref(), Some(b"x\n".as_slice()));
}

#[tokio::test]
async fn async_read_timeout_keeps_partial_banner_and_stop_reason() {
    let (reader, mut writer) = tokio::io::duplex(64);
    writer.write_all(b"partial").await.unwrap();
    let (reason, banner) = read_banner(reader, Duration::from_millis(10)).await;
    assert_eq!(reason, "read timed out");
    assert_eq!(banner.as_deref(), Some(b"partial".as_slice()));
}

#[tokio::test]
async fn connection_close_keeps_collected_bytes() {
    let (reader, mut writer) = tokio::io::duplex(64);
    writer.write_all(b"partial").await.unwrap();
    drop(writer);
    let (reason, banner) = read_banner(reader, Duration::from_secs(1)).await;
    assert_eq!(reason, "peer closed connection");
    assert_eq!(banner.as_deref(), Some(b"partial".as_slice()));
}
