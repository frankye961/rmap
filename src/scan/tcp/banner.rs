//! Passive banner collection with a shared deadline and a bounded byte buffer.

use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant as Deadline, timeout_at};

const READ_CHUNK_BYTES: usize = 64;
const MAX_BANNER_BYTES: usize = 512;

pub(super) async fn read_banner(
    mut stream: impl AsyncRead + Unpin,
    timeout: Duration,
) -> (String, Option<Vec<u8>>) {
    let mut buffer = [0; READ_CHUNK_BYTES];
    let mut collected = Vec::new();
    let deadline = Deadline::now() + timeout;
    while collected.len() < MAX_BANNER_BYTES {
        // One deadline bounds the entire banner, including repeated short reads.
        if Deadline::now() >= deadline {
            return banner_result(&collected, "read timed out");
        }
        let capacity = buffer.len().min(MAX_BANNER_BYTES - collected.len());
        let read = match timeout_at(deadline, stream.read(&mut buffer[..capacity])).await {
            Ok(read) => read,
            Err(_) => return banner_result(&collected, "read timed out"),
        };
        match read {
            Ok(0) => return banner_result(&collected, "peer closed connection"),
            Ok(bytes_read) => {
                collected.extend_from_slice(&buffer[..bytes_read]);
                if collected.contains(&b'\n') || collected.len() >= MAX_BANNER_BYTES {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return banner_result(&collected, "read timed out");
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return banner_result(&collected, &format!("read error: {error}")),
        }
    }
    banner_result(&collected, "")
}

pub(super) fn banner_result(data: &[u8], stop_reason: &str) -> (String, Option<Vec<u8>>) {
    let observation = if data.is_empty() && stop_reason.is_empty() {
        "no banner received".to_string()
    } else {
        stop_reason.to_string()
    };
    (observation, Some(data.to_vec()))
}
