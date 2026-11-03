//! Registration records advertised by a portmapper DUMP reply.

/// One advertised registration, separate from a measured open-port result.
/// Fields retain their unsigned 32-bit wire values for validation during parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcMapping {
    /// RPC program identifier, rather than a software product name.
    pub program: u32,
    /// Registered RPC program version, rather than a software release version.
    pub program_version: u32,
    /// IP transport protocol number: TCP is 6 and UDP is 17.
    pub protocol: u32,
    /// Advertised port; the parser must check its range before using it as a u16.
    pub port: u32,
}
