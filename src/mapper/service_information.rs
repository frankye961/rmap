//! Map parsed TCP service fields into owned identification data and scan results.

use crate::model::service_information::ServiceInformation;
use crate::model::{ScanMode, ScanResult};

pub fn map_tcp_service(
    service: &str,
    product: Option<&str>,
    version: Option<&str>,
    comments: Option<&str>,
) -> ServiceInformation {
    ServiceInformation {
        transport: ScanMode::Tcp,
        service: Some(service.to_string()),
        product: product.map(str::to_string),
        version: version.map(str::to_string),
        observation: comments.filter(|text| !text.is_empty()).map(str::to_string),
    }
}

pub fn apply_service_information(result: &mut ScanResult, information: ServiceInformation) {
    result.service = information.service.clone();
    result.service_information = Some(information);
}
