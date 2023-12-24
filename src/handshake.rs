use crate::crypto;

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Complete,
    NeedRead,
    NeedWrite
}

#[derive(Debug, Clone)]
pub struct Result {
    pub state: State,
    pub output: Option<Vec<u8>>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Secrets {
    pub rx: crypto::Secret,
    pub tx: crypto::Secret,
}