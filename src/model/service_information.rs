use crate::model::ScanMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInformation {
    pub transport: ScanMode,
    pub service: Option<String>,
    /// Optional comments advertised in the identification line, not the read stop reason.
    pub observation: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}
