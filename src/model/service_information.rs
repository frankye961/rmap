#[derive(Debug)]
pub struct ServiceInformation {
    pub port: u16,
    pub transport: ScanMode,
    pub service: Option<String>,
    pub banner: Option<Vec<u8>>,
    pub observation: Option<String>,
    pub ai_analysis: Option<AiAnalysis>,
}
