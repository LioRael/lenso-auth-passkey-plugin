//! Portable `WebAuthn` passkey ceremony and credential-management role.

#[allow(dead_code)]
mod contract;

mod generated {
    include!("generated.rs");
}

pub use generated::*;
