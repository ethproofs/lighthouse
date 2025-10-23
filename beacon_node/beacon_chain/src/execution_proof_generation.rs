//! Execution proof generation and verification
//!
//! This module handles the generation and verification of execution proofs.
//! Currently implements dummy proof generation, but will be replaced with
//! actual proof generation from zkVMs or other proof systems.
use crate::verification_keys::VerificationKeyStore;
use crate::verifiers::VerifierStore;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use std::io::{Cursor, Read};
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, warn};
use types::{
    EthSpec, ExecutionPayload, ExecutionProof, Hash256,
    execution_proof_subnet_id::ExecutionProofSubnetId,
};
use uuid::Uuid;
use zip::ZipArchive;

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

/// Represents a single proof file extracted from the ZIP archive
#[derive(Debug, Clone)]
pub struct ProofFile {
    /// UUID bytes identifying the prover that generated this proof (16 bytes)
    /// Extracted from filename pattern: {name}_{uuid}.bin
    pub prover_id: [u8; 16],
    /// The binary content of the proof file
    pub data: Vec<u8>,
}

/// Collection of proof files extracted from a ZIP archive
#[derive(Debug)]
pub struct ProofArchive {
    /// All proof files extracted from the archive
    pub files: Vec<ProofFile>,
}

impl ProofArchive {
    /// Find a proof file by its prover_id
    pub fn find_by_prover(&self, prover_id: &[u8; 16]) -> Option<&ProofFile> {
        self.files.iter().find(|f| &f.prover_id == prover_id)
    }
}

/// Extract prover_id from filename pattern: {name}_{uuid}.bin or {name}_{uuid}.{ext}
///
/// Example: "brevis_4eb78a0b-61c1-464f-80f2-20f1f56aea73.bin" -> [4e, b7, 8a, 0b, ...]
fn extract_prover_id_from_filename(filename: &str) -> Result<[u8; 16], String> {
    // Get the file stem (filename without extension)
    let path = Path::new(filename);
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("Invalid filename: {}", filename))?;

    // Split on '_' and get the second part (index [1]) which should be the UUID
    let parts: Vec<&str> = file_stem.split('_').collect();
    let uuid_str = if parts.len() >= 2 {
        parts[1]
    } else {
        return Err(format!(
            "Filename '{}' does not match pattern {{name}}_{{uuid}}",
            filename
        ));
    };

    // Parse the UUID string
    let uuid = Uuid::parse_str(uuid_str).map_err(|e| {
        format!(
            "Failed to parse UUID '{}' from filename '{}': {}",
            uuid_str, filename, e
        )
    })?;

    // Convert UUID to bytes
    Ok(*uuid.as_bytes())
}

/// Extract all files from a ZIP archive
fn extract_zip_archive(zip_bytes: &[u8]) -> Result<ProofArchive, String> {
    // Create a cursor over the bytes to allow reading
    let cursor = Cursor::new(zip_bytes);

    // Open the ZIP archive
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| format!("Failed to open ZIP archive: {}", e))?;

    let mut files = Vec::new();

    // Iterate through all files in the archive
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Failed to access file at index {}: {}", i, e))?;

        // Skip directories
        if file.is_dir() {
            continue;
        }

        let filename = file.name().to_string();

        // Extract prover_id from filename pattern: {name}_{uuid}.bin
        let prover_id = extract_prover_id_from_filename(&filename)?;

        // Read the file contents into a buffer
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| format!("Failed to read file '{}': {}", filename, e))?;

        debug!(
            filename = %filename,
            prover_id = ?prover_id,
            size_bytes = data.len(),
            "Extracted proof file from ZIP archive"
        );

        files.push(ProofFile { prover_id, data });
    }

    if files.is_empty() {
        return Err("ZIP archive contains no files".to_string());
    }

    debug!(
        file_count = files.len(),
        "Successfully extracted all files from ZIP archive"
    );

    Ok(ProofArchive { files })
}

/// Download and extract proofs from Ethproofs for PoC implementation.
///
/// TODO(zkproofs): Remove with actual proof generation.
///
/// This accepts the block hash and returns the extracted proof files.
/// The API response should be a ZIP file containing multiple binary proof files.
///
async fn download_proofs_from_ethproofs(
    block_hash: types::ExecutionBlockHash,
) -> Result<ProofArchive, String> {
    const MAX_RETRIES: u32 = 1; // Set to 1 for testing, change to 10 for production.
    const INITIAL_DELAY_MS: u64 = 100;
    const MAX_DELAY_MS: u64 = 5000;

    let client = reqwest::Client::new();
    let url = format!(
        "https://ethproofs.org/api/v0/proofs/download/block/{}",
        block_hash
    );

    let mut delay_ms = INITIAL_DELAY_MS;

    for attempt in 1..=MAX_RETRIES {
        debug!(
            block_hash = %block_hash,
            attempt,
            delay_ms,
            "Attempting to download proofs from Ethproofs"
        );

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        match response.status() {
            StatusCode::OK => {
                debug!(
                    block_hash = %block_hash,
                    attempt,
                    "Successfully downloaded proofs from Ethproofs"
                );

                // Download the ZIP file as bytes
                let zip_bytes = response
                    .bytes()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;

                // Extract the ZIP contents
                return extract_zip_archive(&zip_bytes);
            }
            StatusCode::NOT_FOUND => {
                if attempt == MAX_RETRIES {
                    return Err(format!(
                        "No proofs found for block {} after {} attempts",
                        block_hash, MAX_RETRIES
                    ));
                }

                debug!(
                    block_hash = %block_hash,
                    attempt,
                    next_delay_ms = delay_ms,
                    "Proofs not ready yet, retrying..."
                );

                // Wait before retrying
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

                // Exponential backoff: double the delay, up to MAX_DELAY_MS
                delay_ms = (delay_ms * 2).min(MAX_DELAY_MS);
            }
            status => {
                return Err(format!(
                    "Request failed with status: {} for block {}",
                    status, block_hash
                ));
            }
        }
    }

    Err(format!(
        "Failed to download proofs for block {} after {} attempts",
        block_hash, MAX_RETRIES
    ))
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

    // TEMPORARY FOR TESTING: Only generate proofs for blocks ending in '0' (1/10 blocks)
    if block_number % 10 != 0 {
        debug!(
            block_number,
            "Skipping proof generation - block number does not end in '0'"
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
        "Block number ends in '0' - proceeding with proof generation"
    );

    // HARDCODED FOR TESTING: Override execution_block_hash for proof download
    let hardcoded_hash = types::ExecutionBlockHash::from(
        Hash256::from_str("0xe984074498ffba32c502b59a0324e98c6b8c22527c9a7339c635ddcd65997211")
            .expect("Valid hardcoded hash"),
    );
    debug!(
        original_hash = ?execution_block_hash,
        hardcoded_hash = ?hardcoded_hash,
        "Using hardcoded execution block hash for testing proof download"
    );

    // Download proofs from Ethproofs for PoC implementation.
    let (proof_data, prover_id) = match download_proofs_from_ethproofs(hardcoded_hash).await {
        Ok(archive) => {
            debug!(
                block_number,
                subnet_id = *proof_id,
                file_count = archive.files.len(),
                "Downloaded proof archive from Ethproofs"
            );

            // Use the first file from the archive to test implementation.
            // The should be a brevis proof for testing purposes.
            if let Some(first_file) = archive.files.first() {
                debug!(
                    prover_id = ?first_file.prover_id,
                    size_bytes = first_file.data.len(),
                    "Successfully using proof data from Ethproofs"
                );
                (first_file.data.clone(), first_file.prover_id)
            } else {
                debug!("No proof files in archive, using fallback dummy data");
                (dummy_data.clone(), [0u8; 16])
            }
        }
        Err(e) => {
            debug!(
                error = %e,
                block_number,
                "Failed to download proofs from Ethproofs, using fallback dummy data"
            );
            (dummy_data.clone(), [0u8; 16])
        }
    };

    let proof = ExecutionProof::new(
        block_root,
        execution_block_hash,
        proof_id,
        1,
        prover_id,
        proof_data,
    );

    // TEMPORARY FOR TESTING: Validate the proof immediately after generation
    debug!(
        block_number,
        prover_id = ?proof.prover_id,
        "Testing proof validation immediately after generation"
    );
    let is_valid = validate_proof(&proof);
    debug!(
        block_number,
        prover_id = ?proof.prover_id,
        validation_result = is_valid,
        "Proof validation test completed"
    );

    proof
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
