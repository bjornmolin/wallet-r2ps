use crate::domain::ServiceRequestError;
use problem_details::ProblemDetails;
use serde_json::{Map, Value, json};

/// Specifies in what client response an error will be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorVisibility {
    /// Error is only reported in the WorkerResponse (not returned to client in JWE/JWS)
    Worker,
    /// Error is only reported in the outerResponse
    Outer,
    /// Error is only reported in the encrypted innerResponse
    Inner,
}

#[derive(Debug, Clone)]
pub struct WorkerError {
    pub visibility: ErrorVisibility,
    pub reason: String,
}

impl WorkerError {
    pub fn decode(reason: &str) -> Self {
        Self {
            visibility: ErrorVisibility::Worker,
            reason: reason.to_string(),
        }
    }

    pub fn dispatch(err: ServiceRequestError) -> Self {
        let visibility = match err {
            ServiceRequestError::UnsupportedContext => ErrorVisibility::Outer,
            _ => ErrorVisibility::Inner,
        };
        Self {
            visibility,
            reason: format!("{:?}", err),
        }
    }

    pub fn encode(reason: &str) -> Self {
        Self {
            visibility: ErrorVisibility::Worker,
            reason: reason.to_string(),
        }
    }

    pub fn to_problem_details_json(&self, request_id: &str) -> String {
        let mut extensions: Map<String, Value> = Map::new();
        extensions.insert("request_id".to_string(), json!(request_id));

        let details = ProblemDetails::new()
            .with_title("Error processing request")
            .with_detail(self.reason.clone())
            .with_extensions(extensions);

        serde_json::to_string(&details).unwrap_or_else(|_| "{}".to_string())
    }
}
