use crate::domain::WorkerResponseJws;

pub trait WorkerResponseSpiPort {
    fn send(&self, worker_response: WorkerResponseJws) -> Result<(), WorkerResponseError>;
}

#[derive(Debug)]
pub enum WorkerResponseError {
    ConnectionError,
    // TODO
}
