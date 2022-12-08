#![no_std]

// pub mod btree;

#[derive(Debug, Clone, Copy)]
pub enum RuleAction {
    Allow,
    Deny,
    Redirect,
}

#[repr(packed)]
#[derive(Debug, Clone, Copy)]
pub struct RuleDefinition {
    pub start_port: u16,
    pub end_port: u16,
    pub protocol: Option<u8>,
    pub enabled: bool,
    pub action: RuleAction
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RuleDefinition {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BackendPorts {
    pub ports: [u16; 4],
    pub next: usize, // Allows round robin
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for BackendPorts {}