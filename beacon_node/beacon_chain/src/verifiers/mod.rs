//! Execution proof verifiers
//!
//! This module manages different proof verification systems based on prover type.
//! Each verifier implements cryptographic proof verification for a specific zkVM or proof system.

pub mod pico;
pub mod zisk;
pub mod zkm;

use std::collections::HashMap;
use uuid::Uuid;

/// Result type for proof verification
pub type VerificationResult = Result<bool, String>;

/// Trait for proof verifiers
pub trait ProofVerifier: Send + Sync {
    /// Verify a proof given the proof data and verification key
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult
    where
        Self: Sized;

    /// Get the name of this verifier
    fn name() -> &'static str
    where
        Self: Sized;
}

/// Type for verifier function
pub type VerifierFn = fn(&[u8], &[u8]) -> VerificationResult;

/// Verifier entry with name and verification function
pub struct VerifierEntry {
    pub name: &'static str,
    pub verify_fn: VerifierFn,
}

/// Manager for multiple proof verifiers, keyed by prover UUID
#[derive(Default)]
pub struct VerifierStore {
    /// Map of prover_id to verifier function
    verifiers: HashMap<Uuid, VerifierEntry>,
}

impl VerifierStore {
    /// Create a new empty verifier store
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Register a verifier for a specific prover UUID
    pub fn register(&mut self, prover_id: Uuid, name: &'static str, verify_fn: VerifierFn) {
        self.verifiers
            .insert(prover_id, VerifierEntry { name, verify_fn });
    }

    /// Get a verifier entry for a specific prover UUID
    pub fn get(&self, prover_id: &Uuid) -> Option<&VerifierEntry> {
        self.verifiers.get(prover_id)
    }

    /// Check if a verifier exists for a prover
    pub fn contains(&self, prover_id: &Uuid) -> bool {
        self.verifiers.contains_key(prover_id)
    }

    /// Get the number of registered verifiers
    pub fn len(&self) -> usize {
        self.verifiers.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.verifiers.is_empty()
    }

    /// Get all registered prover IDs
    pub fn prover_ids(&self) -> Vec<Uuid> {
        self.verifiers.keys().copied().collect()
    }

    /// Create a store with default verifiers registered
    ///
    /// This registers verifiers for known prover UUIDs
    pub fn with_defaults() -> Self {
        let mut store = Self::new();

        // Register verifiers for known prover UUIDs
        // Current verification_keys directory mapping:
        // - brevis: 4eb78a0b-61c1-464f-80f2-20f1f56aea73 -> Pico verifier
        // - zisk:   33f14a82-47b7-42d7-9bc1-b81a46eea4fe -> ZisK verifier
        // - zkm:    84a01f4b-8078-44cf-b463-90ddcd124960 -> ZKM verifier

        // Register Pico verifier for brevis
        let brevis_uuid =
            Uuid::parse_str("4eb78a0b-61c1-464f-80f2-20f1f56aea73").expect("Valid UUID");
        store.register(
            brevis_uuid,
            pico::PicoVerifier::name(),
            pico::PicoVerifier::verify,
        );

        // Register ZisK verifier
        let zisk_uuid =
            Uuid::parse_str("33f14a82-47b7-42d7-9bc1-b81a46eea4fe").expect("Valid UUID");
        store.register(
            zisk_uuid,
            zisk::ZiskVerifier::name(),
            zisk::ZiskVerifier::verify,
        );

        // Register ZKM verifier
        let zkm_uuid = Uuid::parse_str("84a01f4b-8078-44cf-b463-90ddcd124960").expect("Valid UUID");
        store.register(zkm_uuid, zkm::ZkmVerifier::name(), zkm::ZkmVerifier::verify);

        store
    }
}
