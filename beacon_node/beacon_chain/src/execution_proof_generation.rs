//! Execution proof generation and verification
//!
//! This module handles the generation and verification of execution proofs.
//! Currently implements dummy proof generation, but will be replaced with
//! actual proof generation from zkVMs or other proof systems.
use crate::verification_keys::VerificationKeyStore;
use crate::verifiers::VerifierStore;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use types::{
    EthSpec, ExecutionPayload, ExecutionProof, Hash256,
    execution_proof_subnet_id::ExecutionProofSubnetId,
};
use uuid::Uuid;

/// Global verification key store, loaded once on first access
pub static VERIFICATION_KEY_STORE: Lazy<Option<VerificationKeyStore>> =
    Lazy::new(|| match VerificationKeyStore::load_embedded() {
        Ok(store) => {
            debug!(
                key_count = store.len(),
                prover_ids = ?store.prover_ids(),
                "Loaded verification keys"
            );
            Some(store)
        }
        Err(e) => {
            warn!(error = %e, "Failed to load verification keys");
            None
        }
    });

/// Global verifier store, initialized with default verifiers
pub static VERIFIER_STORE: Lazy<VerifierStore> = Lazy::new(|| {
    let store = VerifierStore::with_defaults();
    debug!(verifier_count = store.len(), "Initialized verifier store");
    store
});

/// Select a random prover_id from available registered verifiers
fn select_random_prover_id() -> [u8; 16] {
    use rand::Rng;

    let available_provers = VERIFIER_STORE.prover_ids();

    if available_provers.is_empty() {
        warn!("No verifiers registered, cannot select prover_id");
        return [0u8; 16];
    }

    let mut rng = rand::rng();
    let random_index = rng.random_range(0..available_provers.len());
    let selected_uuid = available_provers[random_index];

    debug!(
        prover_id = %selected_uuid,
        available_count = available_provers.len(),
        "Randomly selected prover_id"
    );

    *selected_uuid.as_bytes()
}

/// Represents a proof from the Ethproofs proofs list endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Ethproof {
    /// The proof ID from Ethproofs
    proof_id: u64,
    /// The cluster ID that generated this proof (matches against available prover_ids)
    cluster_id: String,
}

/// Represents the response from the Ethproofs proofs list endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofsListResponse {
    proofs: Vec<Ethproof>,
}

/// Fetch the list of proofs for a block from Ethproofs API.
///
/// Polls the endpoint until all 3 proofs are available or a timeout is reached, using exponential backoff.
/// This accepts the block hash and a comma-separated string of cluster IDs to query.
/// Returns all proofs found within the timeout window.
///
async fn fetch_proofs_list(
    block_hash: types::ExecutionBlockHash,
    clusters: String,
) -> Result<Vec<Ethproof>, String> {
    const MAX_WAIT_TIME_SECS: u64 = 30;
    const INITIAL_DELAY_MS: u64 = 100;
    const MAX_DELAY_MS: u64 = 5000;
    const TARGET_PROOF_COUNT: usize = 3;

    let client = reqwest::Client::new();
    let url = format!(
        "https://ethproofs.org/api/v0/proofs?block={}&clusters={}",
        block_hash, clusters
    );

    let start = Instant::now();
    let mut delay_ms = INITIAL_DELAY_MS;
    let mut accumulated_proofs: Vec<Ethproof> = Vec::new();

    loop {
        // Check if we've exceeded max wait time
        if start.elapsed() > Duration::from_secs(MAX_WAIT_TIME_SECS) {
            debug!(
                block_hash = %block_hash,
                accumulated_count = accumulated_proofs.len(),
                "Max wait time reached, proceeding with accumulated proofs"
            );
            if accumulated_proofs.is_empty() {
                return Err(format!(
                    "No proofs found for block {} within {} seconds",
                    block_hash, MAX_WAIT_TIME_SECS
                ));
            }
            return Ok(accumulated_proofs);
        }

        debug!(
            block_hash = %block_hash,
            accumulated_count = accumulated_proofs.len(),
            delay_ms,
            "Polling Ethproofs for proofs"
        );

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        match response.status() {
            StatusCode::OK => {
                let response_data: ProofsListResponse = response
                    .json()
                    .await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;

                // Accumulate new proofs (avoid duplicates by proof_id)
                for proof in response_data.proofs {
                    if !accumulated_proofs
                        .iter()
                        .any(|p| p.proof_id == proof.proof_id)
                    {
                        accumulated_proofs.push(proof);
                    }
                }

                debug!(
                    block_hash = %block_hash,
                    accumulated_count = accumulated_proofs.len(),
                    target_count = TARGET_PROOF_COUNT,
                    "Accumulated proofs from Ethproofs"
                );

                // If we have all target proofs (k), return early
                if accumulated_proofs.len() >= TARGET_PROOF_COUNT {
                    return Ok(accumulated_proofs);
                }
            }
            StatusCode::NOT_FOUND => {
                debug!(
                    block_hash = %block_hash,
                    accumulated_count = accumulated_proofs.len(),
                    "Block not found, retrying..."
                );
            }
            status => {
                return Err(format!(
                    "Request failed with status: {} for block {}",
                    status, block_hash
                ));
            }
        }

        // Wait before retrying
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        // Exponential backoff: double the delay, up to MAX_DELAY_MS
        delay_ms = (delay_ms * 2).min(MAX_DELAY_MS);
    }
}

/// Download a proof binary directly from Ethproofs using the proof_id.
///
/// Returns the binary proof data.
///
async fn download_proof_binary(proof_id: u64) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::new();
    let url = format!("https://ethproofs.org/api/v0/proofs/download/{}", proof_id);

    debug!(proof_id, "Downloading proof binary from Ethproofs");

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    match response.status() {
        StatusCode::OK => {
            let proof_data = response
                .bytes()
                .await
                .map_err(|e| format!("Failed to read response: {}", e))?;

            debug!(
                proof_id,
                size_bytes = proof_data.len(),
                "Successfully downloaded proof binary"
            );

            Ok(proof_data.to_vec())
        }
        StatusCode::NOT_FOUND => Err(format!("Proof {} not found", proof_id)),
        status => Err(format!(
            "Request failed with status: {} for proof {}",
            status, proof_id
        )),
    }
}

/// Generate a proof for an execution payload
///
/// TODO(zkproofs): Currently using Ethproofs API for proofs. Will be replaced with actual proof generation
/// from zkVMs or other proof systems.
///
/// This accepts the concrete ExecutionPayload<E> type which is what the EL expects
/// and can be easily serialized for sending to external systems.
/// The execution_state_witness would be obtained from the EL (e.g., via debug_executionWitness)
pub async fn generate_proof<T: EthSpec>(
    block_root: Hash256,
    payload: &ExecutionPayload<T>,
    execution_state_witness: &[u8],
    proof_id: ExecutionProofSubnetId,
) -> ExecutionProof {
    let execution_block_hash = payload.block_hash();
    let block_number = payload.block_number();

    // Create dummy proof data that includes the subnet information and payload details
    // In a real implementation, this would use the execution_state_witness to generate
    // a cryptographic proof of the payload's validity
    let dummy_data = format!(
        "dummy_proof_subnet_{}_block_{:?}_number_{}_witness_len_{}",
        *proof_id,
        execution_block_hash,
        block_number,
        execution_state_witness.len()
    )
    .into_bytes();

    // TEMPORARY FOR TESTING: Only generate proofs for blocks ending in '00' (1/100 blocks)
    if block_number % 100 != 0 {
        debug!(
            block_number,
            "Skipping proof generation - block number does not end in '00'"
        );
        // Return a minimal dummy proof for non-targeted blocks
        return ExecutionProof::new(
            block_root,
            execution_block_hash,
            proof_id,
            1,
            [0u8; 16], // Placeholder prover_id
            dummy_data.clone(),
        );
    }

    debug!(
        block_number,
        "Block number ends in '00' - proceeding with proof generation"
    );

    // Get available prover IDs as comma-separated string for API query
    let available_prover_ids: Vec<String> = VERIFIER_STORE
        .prover_ids()
        .iter()
        .map(|uuid| uuid.to_string())
        .collect();

    let clusters = available_prover_ids.join(",");

    debug!(
        available_prover_ids = ?available_prover_ids,
        "Available prover IDs for proof query"
    );

    // Fetch proofs list from Ethproofs (polls until we get target proofs or timeout)
    let (proof_data, prover_id_bytes) = match fetch_proofs_list(execution_block_hash, clusters)
        .await
    {
        Ok(proofs) => {
            debug!(
                block_number,
                subnet_id = *proof_id,
                proof_count = proofs.len(),
                "Fetched proofs list from Ethproofs"
            );

            if proofs.is_empty() {
                warn!(
                    block_number,
                    "No proofs returned from Ethproofs, using fallback dummy data"
                );
                (dummy_data.clone(), select_random_prover_id())
            } else {
                use rand::Rng;

                // Try each proof until one verifies
                let mut last_error = String::from("No proofs to try");
                let mut tried_proofs = vec![];
                let mut success_result: Option<(Vec<u8>, [u8; 16])> = None;

                for _ in 0..proofs.len() {
                    if success_result.is_some() {
                        break;
                    }

                    // Randomly select a proof we haven't tried yet
                    let random_index = rand::rng().random_range(0..proofs.len());
                    let proof_entry = &proofs[random_index];

                    // Skip if we've already tried this one
                    if tried_proofs.contains(&proof_entry.proof_id) {
                        continue;
                    }
                    tried_proofs.push(proof_entry.proof_id);

                    debug!(
                        proof_id = proof_entry.proof_id,
                        cluster_id = %proof_entry.cluster_id,
                        "Attempting to download and verify proof"
                    );

                    // Download the proof binary
                    match download_proof_binary(proof_entry.proof_id).await {
                        Ok(proof_binary) => {
                            // Convert cluster_id string to prover_id bytes
                            match Uuid::parse_str(&proof_entry.cluster_id) {
                                Ok(cluster_uuid) => {
                                    let prover_id_bytes = *cluster_uuid.as_bytes();

                                    // Create proof for verification
                                    let test_proof = ExecutionProof::new(
                                        block_root,
                                        execution_block_hash,
                                        proof_id,
                                        1,
                                        prover_id_bytes,
                                        proof_binary.clone(),
                                    );

                                    // Verify the proof
                                    if validate_proof(&test_proof) {
                                        debug!(
                                            proof_id = proof_entry.proof_id,
                                            cluster_id = %proof_entry.cluster_id,
                                            "Proof verification succeeded"
                                        );
                                        success_result = Some((proof_binary, prover_id_bytes));
                                    } else {
                                        debug!(
                                            proof_id = proof_entry.proof_id,
                                            cluster_id = %proof_entry.cluster_id,
                                            "Proof verification failed, trying next proof"
                                        );
                                        last_error = format!(
                                            "Proof {} verification failed",
                                            proof_entry.proof_id
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        cluster_id = %proof_entry.cluster_id,
                                        error = %e,
                                        "Failed to parse cluster_id as UUID"
                                    );
                                    last_error =
                                        format!("Invalid cluster UUID: {}", proof_entry.cluster_id);
                                }
                            }
                        }
                        Err(e) => {
                            debug!(
                                proof_id = proof_entry.proof_id,
                                error = %e,
                                "Failed to download proof, trying next"
                            );
                            last_error =
                                format!("Failed to download proof {}: {}", proof_entry.proof_id, e);
                        }
                    }
                }

                if let Some((binary, bytes)) = success_result {
                    (binary, bytes)
                } else {
                    warn!(
                        block_number,
                        last_error = %last_error,
                        "All proofs failed verification or download, using fallback dummy data"
                    );
                    (dummy_data.clone(), select_random_prover_id())
                }
            }
        }
        Err(e) => {
            debug!(
                error = %e,
                block_number,
                "Failed to fetch proofs from Ethproofs, using fallback dummy data"
            );
            (dummy_data.clone(), select_random_prover_id())
        }
    };

    ExecutionProof::new(
        block_root,
        execution_block_hash,
        proof_id,
        1,
        prover_id_bytes,
        proof_data,
    )
}

/// Validate a proof (Ethproofs placeholder implementation)
///
/// TODO(zkproofs): Implement actual cryptographic proof validation based on version and type
pub fn validate_proof(proof: &ExecutionProof) -> bool {
    match &*VERIFICATION_KEY_STORE {
        Some(store) => {
            // Convert prover_id bytes to Uuid for lookup
            let prover_uuid = Uuid::from_bytes(proof.prover_id);

            match store.get(&prover_uuid) {
                Some(vk) => {
                    debug!(
                        prover_id = %prover_uuid,
                        vk_size = vk.size(),
                        proof_version = proof.version,
                        proof_size = proof.proof_data.len(),
                        "Found verification key for prover"
                    );

                    // Look up the verifier for this prover
                    match VERIFIER_STORE.get(&prover_uuid) {
                        Some(verifier_entry) => {
                            debug!(
                                prover_id = %prover_uuid,
                                verifier = verifier_entry.name,
                                "Found verifier, running cryptographic verification"
                            );

                            // Run the actual cryptographic verification
                            match (verifier_entry.verify_fn)(&proof.proof_data, &vk.vk) {
                                Ok(result) => {
                                    debug!(
                                        prover_id = %prover_uuid,
                                        verification_result = result,
                                        "Verification completed"
                                    );
                                    result
                                }
                                Err(e) => {
                                    warn!(
                                        prover_id = %prover_uuid,
                                        error = %e,
                                        "Verification failed with error"
                                    );
                                    false
                                }
                            }
                        }
                        None => {
                            warn!(
                                prover_id = %prover_uuid,
                                "No verifier registered for this prover, cannot verify proof"
                            );
                            false
                        }
                    }
                }
                None => {
                    warn!(
                        prover_id = %prover_uuid,
                        available_keys = store.len(),
                        "No verification key found for prover"
                    );
                    false
                }
            }
        }
        None => {
            warn!("Verification key store failed to initialize");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        ExecutionBlockHash, ExecutionPayloadBellatrix, FixedBytesExtended, FullPayloadBellatrix,
        Hash256, MainnetEthSpec, Uint256,
    };

    #[tokio::test]
    async fn test_generate_proof() {
        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(5).unwrap();

        // Create a dummy payload for testing
        let payload = FullPayloadBellatrix::<MainnetEthSpec> {
            execution_payload: ExecutionPayloadBellatrix::<MainnetEthSpec> {
                parent_hash: ExecutionBlockHash::zero(),
                fee_recipient: Default::default(),
                state_root: Hash256::zero(),
                receipts_root: Hash256::zero(),
                logs_bloom: Default::default(),
                prev_randao: Hash256::zero(),
                block_number: 12345,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 0,
                extra_data: Default::default(),
                base_fee_per_gas: Uint256::from(1u64),
                block_hash: execution_block_hash,
                transactions: Default::default(),
            },
        };

        let exec_payload = ExecutionPayload::Bellatrix(payload.execution_payload);
        let dummy_witness = b"test_witness_data";
        let proof = generate_proof(Hash256::random(), &exec_payload, dummy_witness, proof_id).await;

        assert_eq!(proof.block_hash, execution_block_hash);
        assert_eq!(proof.subnet_id, proof_id);
        assert_eq!(proof.version, 1);
        assert!(!proof.proof_data.is_empty());
        assert!(validate_proof(&proof));

        // Verify the proof data contains expected information
        let proof_data_str = String::from_utf8_lossy(&proof.proof_data);
        assert!(proof_data_str.contains("subnet_5"));
        assert!(proof_data_str.contains("number_12345"));
        assert!(proof_data_str.contains("witness_len_17")); // 17 is the length of "test_witness_data"
    }

    #[test]
    fn test_validate_proof() {
        let hash = ExecutionBlockHash::from(Hash256::random());

        // Test version 1 proof (supported)
        let v1_proof = ExecutionProof::new(
            Hash256::random(),
            hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            [1u8; 16],
            vec![1, 2, 3],
        );
        assert!(validate_proof(&v1_proof));

        // Test unsupported version
        let v2_proof = ExecutionProof::new(
            Hash256::random(),
            hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            2,
            [2u8; 16],
            vec![7, 8, 9],
        );
        assert!(!validate_proof(&v2_proof)); // Should fail validation for unknown version

        // Test empty data with version 1 (should be invalid)
        let empty_v1 = ExecutionProof::new(
            Hash256::random(),
            hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            [3u8; 16],
            vec![],
        );
        assert!(!validate_proof(&empty_v1));
    }

    #[tokio::test]
    async fn test_generate_proof_different_subnets() {
        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());

        // Create a dummy payload for testing
        let payload = FullPayloadBellatrix::<MainnetEthSpec> {
            execution_payload: ExecutionPayloadBellatrix::<MainnetEthSpec> {
                parent_hash: ExecutionBlockHash::zero(),
                fee_recipient: Default::default(),
                state_root: Hash256::zero(),
                receipts_root: Hash256::zero(),
                logs_bloom: Default::default(),
                prev_randao: Hash256::zero(),
                block_number: 42,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: Default::default(),
                base_fee_per_gas: Uint256::from(0u64),
                block_hash: execution_block_hash,
                transactions: Default::default(),
            },
        };

        let exec_payload = ExecutionPayload::Bellatrix(payload.execution_payload);
        let dummy_witness = b"test_witness_data";

        let proof_0 = generate_proof(
            Hash256::random(),
            &exec_payload,
            dummy_witness,
            ExecutionProofSubnetId::new(0).unwrap(),
        )
        .await;
        let proof_1 = generate_proof(
            Hash256::random(),
            &exec_payload,
            dummy_witness,
            ExecutionProofSubnetId::new(1).unwrap(),
        )
        .await;
        let proof_2 = generate_proof(
            Hash256::random(),
            &exec_payload,
            dummy_witness,
            ExecutionProofSubnetId::new(2).unwrap(),
        )
        .await;

        // All proofs should be for the same block hash
        assert_eq!(proof_0.block_hash, execution_block_hash);
        assert_eq!(proof_1.block_hash, execution_block_hash);
        assert_eq!(proof_2.block_hash, execution_block_hash);

        // But should have different proof IDs and data
        assert_eq!(*proof_0.subnet_id, 0);
        assert_eq!(*proof_1.subnet_id, 1);
        assert_eq!(*proof_2.subnet_id, 2);

        // Proof data should be different for different subnets
        assert_ne!(proof_0.proof_data, proof_1.proof_data);
        assert_ne!(proof_1.proof_data, proof_2.proof_data);

        let data_0 = String::from_utf8_lossy(&proof_0.proof_data);
        let data_1 = String::from_utf8_lossy(&proof_1.proof_data);
        let data_2 = String::from_utf8_lossy(&proof_2.proof_data);

        assert!(data_0.contains("subnet_0"));
        assert!(data_1.contains("subnet_1"));
        assert!(data_2.contains("subnet_2"));
    }

    #[tokio::test]
    async fn test_generate_proof_deterministic() {
        // Test that proof generation is deterministic - same input always produces same output
        let execution_block_hash = ExecutionBlockHash::from(Hash256::from_low_u64_be(12345));
        let proof_id = ExecutionProofSubnetId::new(3).unwrap();

        // Create a specific payload with fixed values
        let payload = FullPayloadBellatrix::<MainnetEthSpec> {
            execution_payload: ExecutionPayloadBellatrix::<MainnetEthSpec> {
                parent_hash: ExecutionBlockHash::from(Hash256::from_low_u64_be(111)),
                fee_recipient: Default::default(),
                state_root: Hash256::from_low_u64_be(222),
                receipts_root: Hash256::from_low_u64_be(333),
                logs_bloom: Default::default(),
                prev_randao: Hash256::from_low_u64_be(444),
                block_number: 555,
                gas_limit: 30_000_000,
                gas_used: 15_000_000,
                timestamp: 1234567890,
                extra_data: b"test_extra_data".to_vec().into(),
                base_fee_per_gas: Uint256::from(7u64),
                block_hash: execution_block_hash,
                transactions: vec![b"tx1".to_vec().into(), b"tx2".to_vec().into()].into(),
            },
        };

        let exec_payload = ExecutionPayload::Bellatrix(payload.execution_payload);
        let witness_data = b"deterministic_witness_data";

        // Generate proof multiple times with same input
        let block_root = Hash256::random();
        let proof1 = generate_proof(block_root, &exec_payload, witness_data, proof_id).await;
        let proof2 = generate_proof(block_root, &exec_payload, witness_data, proof_id).await;
        let proof3 = generate_proof(block_root, &exec_payload, witness_data, proof_id).await;

        // All proofs should be identical
        assert_eq!(proof1.block_hash, proof2.block_hash);
        assert_eq!(proof1.block_hash, proof3.block_hash);

        assert_eq!(proof1.subnet_id, proof2.subnet_id);
        assert_eq!(proof1.subnet_id, proof3.subnet_id);

        assert_eq!(proof1.version, proof2.version);
        assert_eq!(proof1.version, proof3.version);

        // Most importantly, proof data should be identical
        assert_eq!(proof1.proof_data, proof2.proof_data);
        assert_eq!(proof1.proof_data, proof3.proof_data);

        // Verify the content is as expected
        let proof_str = String::from_utf8_lossy(&proof1.proof_data);
        assert!(proof_str.contains("subnet_3"));
        assert!(proof_str.contains("number_555"));
        assert!(proof_str.contains("witness_len_26"));

        // Now test that different inputs produce different proofs
        let different_witness = b"different_witness_data";
        let proof_different =
            generate_proof(block_root, &exec_payload, different_witness, proof_id).await;

        // Same block hash and subnet, but different proof data
        assert_eq!(proof_different.block_hash, proof1.block_hash);
        assert_eq!(proof_different.subnet_id, proof1.subnet_id);
        assert_ne!(proof_different.proof_data, proof1.proof_data);
    }
}
