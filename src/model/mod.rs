//! Structured scan measurements and separate AI analysis data.

mod ai;
pub mod rpc;
pub mod service_information;
pub mod smb;
pub mod syn;

use self::rpc::RpcMapping;
use self::service_information::ServiceInformation;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    Tcp,
    Udp,
    Syn,
}

impl ScanMode {
    /// SYN is a scan technique over TCP, not a separate transport protocol.
    pub fn transport(self) -> Self {
        match self {
            Self::Syn => Self::Tcp,
            mode => mode,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Syn => "syn",
        }
    }
}

#[derive(Debug)]
pub struct ScanResult {
    pub port: u16,
    pub transport: ScanMode,
    pub status: PortStatus,
    pub service: Option<String>,
    pub elapsed: Duration,
    pub error: Option<String>,
    pub observation: Option<String>,
    pub banner: Option<Vec<u8>>,
    pub service_information: Option<ServiceInformation>,
    /// Advertised registrations, separate from measured port states.
    /// None means no successful enumeration; Some(empty) means an empty DUMP result.
    pub rpc_mappings: Option<Vec<RpcMapping>>,
}

impl ScanResult {
    /// Start with measured connection fields and no inferred service or response evidence.
    pub fn new(port: u16, transport: ScanMode, status: PortStatus, elapsed: Duration) -> Self {
        Self {
            port,
            transport,
            status,
            elapsed,
            service: None,
            error: None,
            observation: None,
            banner: None,
            service_information: None,
            rpc_mappings: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    /// Tentative label for a connection timeout; filtering is not proven.
    Filtered,
    /// No UDP response; the port may be open or filtered.
    OpenOrFiltered,
    Unknown,
}

pub use ai::{AiAnalysis, CveCandidate, WebSource};
