//! SMB2 negotiation, with separate request, transport, and validation modules.

use std::sync::OnceLock;

mod constants;
mod reply;
mod request;
mod transport;

pub(super) use constants::{INITIAL_MESSAGE_ID, MAX_REPLY_BYTES};
pub(super) use reply::response_information;
pub(super) use transport::probe;

/// Reuse one randomly generated client identifier across this process's SMB probes.
pub(super) fn client_guid() -> Result<[u8; 16], String> {
    static GUID: OnceLock<Result<[u8; 16], String>> = OnceLock::new();
    GUID.get_or_init(|| {
        let mut _guid = [0; 16];
        getrandom::fill(&mut _guid)
            .map_err(|_error| format!("Failed to generate SMB client GUID: {_error}"))?;
        Ok(_guid)
    })
    .clone()
}

/// Select an initial candidate port; only a validated response identifies SMB.
pub(super) fn is_smb_candidate(_port: u16) -> bool {
    _port == constants::DIRECT_TCP_PORT
}

#[cfg(test)]
#[path = "../../../tests/scan/smb.rs"]
mod tests;
