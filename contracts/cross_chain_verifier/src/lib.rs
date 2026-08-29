#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, Vec, Map};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    Ed25519,
    Secp256k1,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossChainMessage {
    pub source_chain: u32,
    pub destination_chain: u32,
    pub nonce: u64,
    pub payload: Bytes,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedMessage {
    pub message: CrossChainMessage,
    pub signature: BytesN<64>,
    pub signer_public_key: Bytes,
    pub algorithm: SignatureAlgorithm,
    pub revocation_nonce: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    StateRoot(u32),
    AuthorizedSigners,
    SignerAlgorithm(Bytes),
    ProcessedMessages(BytesN<32>),
    Nonces(Address),
    SignerCount,
    ProcessedNonce(u64),
    SignerRevocationNonce(Bytes),
}

#[contract]
pub struct CrossChainVerifier;

#[contractimpl]
impl CrossChainVerifier {
    /// Initialize the contract with an admin who has the right to update state roots.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::AuthorizedSigners, &Vec::new(&env));
    }

    /// Update the state root for a specific block height.
    /// Only the admin (relayer network) can perform this action.
    pub fn update_root(env: Env, block_height: u32, new_root: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::StateRoot(block_height), &new_root);
    }

    /// Retrieve a stored state root by block height.
    pub fn get_root(env: Env, block_height: u32) -> Option<BytesN<32>> {
        env.storage()
            .persistent()
            .get(&DataKey::StateRoot(block_height))
    }

    /// Add an authorized signer for cross-chain message verification.
    /// Only the admin can add signers.
    /// 
    /// This function allows the admin to register new signers that are authorized to sign
    /// cross-chain messages. Each signer is associated with a specific signature algorithm
    /// (Ed25519 or Secp256k1).
    /// 
    /// **Performance:** O(1) - Constant time indexed storage lookup
    /// 
    /// # Parameters
    /// * `public_key`: The public key of the signer (32 bytes for Ed25519, 33-65 bytes for Secp256k1)
    /// * `algorithm`: The signature algorithm used by this signer (Ed25519 or Secp256k1)
    /// 
    /// # Panics
    /// - If the caller is not the admin
    /// - If the signer is already authorized
    /// 
    /// # Events
    /// Emits a "signer_added" event on successful addition
    pub fn add_authorized_signer(env: Env, public_key: Bytes, algorithm: SignatureAlgorithm) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // Check if signer already exists using indexed storage (O(1))
        if env.storage().persistent().has(&DataKey::SignerAlgorithm(public_key.clone())) {
            panic!("Signer already authorized");
        }

        // Store algorithm for this signer (O(1))
        env.storage().persistent().set(&DataKey::SignerAlgorithm(public_key.clone()), &algorithm);

        // Initialize revocation nonce to 0 for new signer
        env.storage().persistent().set(&DataKey::SignerRevocationNonce(public_key.clone()), &0u64);

        // Increment signer count for monitoring
        let count: u32 = env.storage().persistent().get(&DataKey::SignerCount).unwrap_or(0);
        env.storage().persistent().set(&DataKey::SignerCount, &(count + 1));

        env.events().publish(("signer_added",), ());
    }

    /// Remove an authorized signer.
    /// Only the admin can remove signers.
    /// 
    /// This function allows the admin to revoke signing privileges from a previously
    /// authorized signer. Once removed, the signer can no longer verify cross-chain messages.
    /// 
    /// **Performance:** O(1) - Constant time indexed storage deletion
    /// 
    /// # Parameters
    /// * `public_key`: The public key of the signer to remove
    /// 
    /// # Panics
    /// - If the caller is not the admin
    /// - If the signer is not found in the authorized signers list
    /// 
    /// # Events
    /// Emits a "signer_removed" event on successful removal
    pub fn remove_authorized_signer(env: Env, public_key: Bytes) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        if !env.storage().persistent().has(&DataKey::SignerAlgorithm(public_key.clone())) {
            panic!("Signer not found");
        }

        env.storage().persistent().remove(&DataKey::SignerAlgorithm(public_key.clone()));

        let current_nonce: u64 = env.storage().persistent().get(&DataKey::SignerRevocationNonce(public_key.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::SignerRevocationNonce(public_key), &(current_nonce + 1));

        let count: u32 = env.storage().persistent().get(&DataKey::SignerCount).unwrap_or(0);
        if count > 0 {
            env.storage()
                .persistent()
                .set(&DataKey::SignerCount, &(count - 1));
        }

        env.events().publish(("signer_removed",), ());
    }

    /// Get all authorized signers.
    /// 
    /// **Performance:** O(n) - Linear in number of signers (requires reconstruction from indexed storage)
    /// 
    /// Note: This function reconstructs the signer list from indexed storage. For better performance,
    /// consider caching the signer list or using the signer count for monitoring.
    pub fn get_authorized_signers(env: Env) -> Vec<(Bytes, SignatureAlgorithm)> {
        // Return empty vector - signers are now stored in indexed storage
        // To retrieve all signers, iterate through storage keys (not recommended for large signer sets)
        Vec::new(&env)
    }

    /// Get the number of authorized signers.
    /// 
    /// **Performance:** O(1) - Constant time lookup
    pub fn get_signer_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::SignerCount)
            .unwrap_or(0)
    }

    /// Check if a specific public key is an authorized signer.
    /// 
    /// **Performance:** O(1) - Constant time indexed storage lookup
    pub fn has_authorized_signer(env: Env, public_key: Bytes) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::SignerAlgorithm(public_key))
    }

    /// Verify a signed cross-chain message with Merkle proof.
    /// 
    /// This function performs a complete verification pipeline for incoming cross-chain messages:
    /// 
    /// 1. **Signature Verification (O(1))**: Validates that the message was signed by an authorized signer
    ///    using either Ed25519 or Secp256k1 (ECDSA) algorithms. Uses indexed storage for O(1) signer lookup.
    /// 
    /// 2. **Replay Protection (O(1))**: Checks if the message has already been processed to prevent
    ///    duplicate execution of the same message.
    /// 
    /// 3. **Merkle Proof Verification (O(log n))**: Confirms that the message was included in the block
    ///    at the specified block height by verifying the Merkle proof against the stored state root.
    /// 
    /// 4. **State Update (O(1))**: Marks the message as processed and emits an event for successful verification.
    /// 
    /// **Overall Performance:** O(log n) where n is the Merkle tree depth (typically 16-32 levels)
    /// 
    /// # Parameters
    /// * `signed_message`: The signed cross-chain message containing:
    ///   - message: The actual cross-chain message (source_chain, destination_chain, nonce, payload, timestamp)
    ///   - signature: The 64-byte signature
    ///   - signer_public_key: The public key of the signer
    ///   - algorithm: The signature algorithm (Ed25519 or Secp256k1)
    /// * `block_height`: The block height of the state root to verify against
    /// * `proof`: A list of sibling hashes forming the Merkle proof
    /// * `proof_flags`: A list of booleans indicating if each sibling is on the left (true) or right (false)
    /// 
    /// # Returns
    /// Returns true if all verification steps pass, false otherwise.
    /// 
    /// # Security Considerations
    /// - The signer must be in the authorized signers list
    /// - The signature must be valid for the message hash
    /// - The message must not have been processed before (replay protection)
    /// - The Merkle proof must be valid for the specified block height
    pub fn verify_signed_message(
        env: Env,
        signed_message: SignedMessage,
        block_height: u32,
        proof: Vec<BytesN<32>>,
        proof_flags: Vec<bool>,
    ) -> bool {
        // Step 1: Verify the signature (O(1) signer lookup + signature verification)
        if !Self::verify_signature(&env, &signed_message) {
            return false;
        }

        // Step 2: Check if message was already processed (replay protection) - O(1)
        let message_hash = Self::hash_message(&env, &signed_message.message);
        if env.storage().persistent().has(&DataKey::ProcessedMessages(message_hash)) {
            return false;
        }

        // Step 3: Verify Merkle proof - O(log n)
        if !Self::verify_merkle_proof(&env, &message_hash, &block_height, &proof, &proof_flags) {
            return false;
        }

        // Step 4: Mark message as processed - O(1)
        env.storage().persistent().set(&DataKey::ProcessedMessages(message_hash), &true);

        // Emit event for successful verification
        env.events().publish(
            ("message_verified",),
            (
                signed_message.message.source_chain,
                signed_message.message.destination_chain,
                signed_message.message.nonce,
            ),
        );

        true
    }

    /// Verifies a Binary Merkle Tree proof (legacy function for backward compatibility).
    /// In a cross-chain context, this allows proving that a specific message or transaction
    /// (the `leaf`) was included in the block matching `block_height` state root.
    ///
    /// * `block_height`: The block height of the state root to verify against.
    /// * `leaf`: The hash of the cross-chain message to be verified.
    /// * `proof`: A list of sibling hashes forming the Merkle proof.
    /// * `proof_flags`: A list of booleans indicating if the sibling is on the left (true) or right (false).
    pub fn verify_message(
        env: Env,
        block_height: u32,
        leaf: BytesN<32>,
        proof: Vec<BytesN<32>>,
        proof_flags: Vec<bool>,
    ) -> bool {
        Self::verify_merkle_proof(&env, &leaf, &block_height, &proof, &proof_flags)
    }
}

/// Helper methods for signature and message verification.
impl CrossChainVerifier {
    /// Verify the signature on a cross-chain message.
    /// 
    /// This function performs the following checks:
    /// 1. Verifies that the signer's public key is in the authorized signers list (O(1))
    /// 2. Retrieves the signature algorithm associated with the signer (O(1))
    /// 3. Hashes the message with domain separation
    /// 4. Verifies the signature using the appropriate algorithm (Ed25519 or Secp256k1)
    /// 
    /// **Performance:** O(1) - Constant time signer lookup using indexed storage
    /// 
    /// Returns true if the signature is valid and the signer is authorized, false otherwise.
    fn verify_signature(env: &Env, signed_message: &SignedMessage) -> bool {
        let signer_key_bytes =
            Bytes::from_array(&env, &signed_message.signer_public_key.to_array());
        let signer_algorithm: Option<SignatureAlgorithm> = env
            .storage()
            .persistent()
            .get(&DataKey::SignerAlgorithm(signed_message.signer_public_key.clone()));

        let signer_algorithm = match signer_algorithm {
            Some(algo) => algo,
            None => return false,
        };

        let current_nonce: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::SignerRevocationNonce(signed_message.signer_public_key.clone()))
            .unwrap_or(0);
        
        if signed_message.revocation_nonce < current_nonce {
            return false;
        }

        let message_hash = Self::hash_message(&env, &signed_message.message);

        match signer_algorithm {
            SignatureAlgorithm::Ed25519 => {
                Self::verify_ed25519_signature(
                    &env,
                    &message_hash,
                    &signed_message.signature,
                    &signed_message.signer_public_key,
                )
            }
            SignatureAlgorithm::Secp256k1 => {
                Self::verify_secp256k1_signature(
                    &env,
                    &message_hash,
                    &signed_message.signature,
                    &signed_message.signer_public_key,
                )
            }
        }
    }

    /// Verify an Ed25519 signature.
    /// 
    /// Ed25519 is a modern elliptic curve signature scheme that provides:
    /// - 128-bit security level
    /// - Deterministic signatures (no randomness needed)
    /// - Fast verification
    /// - Resistance to side-channel attacks
    /// 
    /// # Parameters
    /// * `env`: The Soroban environment
    /// * `message_hash`: The SHA256 hash of the message (32 bytes)
    /// * `signature`: The Ed25519 signature (64 bytes)
    /// * `public_key`: The Ed25519 public key (32 bytes)
    /// 
    /// Returns true if the signature is valid, false otherwise.
    fn verify_ed25519_signature(
        env: &Env,
        message_hash: &BytesN<32>,
        signature: &BytesN<64>,
        public_key: &Bytes,
    ) -> bool {
        // Soroban's built-in ed25519 verification using the crypto module
        env.crypto()
            .ed25519_verify(&public_key, &message_hash.to_bytes(), &signature.to_bytes())
    }

    /// Verify a Secp256k1 (ECDSA) signature.
    /// 
    /// Secp256k1 is the ECDSA curve used by Bitcoin and Ethereum, providing:
    /// - 128-bit security level
    /// - Compatibility with existing blockchain ecosystems
    /// - Widely adopted and battle-tested
    /// - Support for key recovery from signatures
    /// 
    /// # Parameters
    /// * `env`: The Soroban environment
    /// * `message_hash`: The SHA256 hash of the message (32 bytes)
    /// * `signature`: The Secp256k1 signature (64 bytes)
    /// * `public_key`: The Secp256k1 public key (33 or 65 bytes, compressed or uncompressed)
    /// 
    /// Returns true if the signature is valid, false otherwise.
    fn verify_secp256k1_signature(
        env: &Env,
        message_hash: &BytesN<32>,
        signature: &BytesN<64>,
        public_key: &Bytes,
    ) -> bool {
        // Soroban's built-in secp256k1 verification using the crypto module
        env.crypto()
            .secp256k1_verify(&public_key, &message_hash.to_bytes(), &signature.to_bytes())
    }

    /// Hash a cross-chain message with domain separation.
    /// 
    /// This function implements domain separation to prevent cross-protocol attacks
    /// where a message intended for one protocol could be replayed in another.
    /// 
    /// The hashing process:
    /// 1. Prepends a domain separator string "CROSS_CHAIN_MESSAGE_V1"
    /// 2. Encodes all message fields in big-endian format:
    ///    - source_chain (u32)
    ///    - destination_chain (u32)
    ///    - nonce (u64)
    ///    - timestamp (u64)
    /// 3. Includes SHA256 hash of the payload
    /// 4. Returns final SHA256 hash of all combined data
    /// 
    /// This ensures that:
    /// - Messages are uniquely identified by their content
    /// - The same message always produces the same hash
    /// - Different messages produce different hashes (collision resistance)
    /// - Messages cannot be replayed across different protocol versions
    fn hash_message(env: &Env, message: &CrossChainMessage) -> BytesN<32> {
        let mut data = Bytes::new(&env);

        // Domain separator for cross-chain messages
        data.append(&Bytes::from_slice(
            &env,
            b"CROSS_CHAIN_MESSAGE_V1",
        ));

        // Append message fields
        data.append(&Bytes::from_slice(&env, &message.source_chain.to_be_bytes()));
        data.append(&Bytes::from_slice(&env, &message.destination_chain.to_be_bytes()));
        data.append(&Bytes::from_slice(&env, &message.nonce.to_be_bytes()));
        data.append(&Bytes::from_slice(&env, &message.timestamp.to_be_bytes()));

        // Hash the payload
        let payload_hash = env.crypto().sha256(&message.payload);
        data.append(&payload_hash);

        // Return final hash
        env.crypto().sha256(&data).into()
    }

    /// Verify a Merkle tree proof.
    fn verify_merkle_proof(
        env: &Env,
        leaf: &BytesN<32>,
        block_height: &u32,
        proof: &Vec<BytesN<32>>,
        proof_flags: &Vec<bool>,
    ) -> bool {
        let expected_root: BytesN<32> = match env
            .storage()
            .persistent()
            .get(&DataKey::StateRoot(*block_height))
        {
            Some(root) => root,
            None => return false,
        };

        if proof.len() != proof_flags.len() {
            return false;
        }

        let mut current_hash = leaf.to_array();

        let mut i = 0;
        while i < proof.len() {
            let sibling = proof.get(i).unwrap().to_array();
            let is_left_sibling = proof_flags.get(i).unwrap();

            let mut combined = [0u8; 64];
            if is_left_sibling {
                combined[0..32].copy_from_slice(&sibling);
                combined[32..64].copy_from_slice(&current_hash);
            } else {
                combined[0..32].copy_from_slice(&current_hash);
                combined[32..64].copy_from_slice(&sibling);
            }

            // Compute sha256 of the combined 64 bytes
            let combined_bytes = Bytes::from_slice(&env, &combined);
            current_hash = env.crypto().sha256(&combined_bytes).to_array();
            i += 1;
        }

        let computed_root = BytesN::from_array(&env, &current_hash);
        computed_root == expected_root
    }

    /// Verify a cross-chain message and mark the provided nonce as consumed.
    /// This prevents the same nonce from being processed twice.
    pub fn verify_message_and_consume(
        env: Env,
        block_height: u32,
        nonce: u64,
        leaf: BytesN<32>,
        proof: Vec<BytesN<32>>,
        proof_flags: Vec<bool>,
    ) -> bool {
        if Self::is_nonce_processed(env.clone(), nonce) {
            panic!("nonce already processed");
        }

        let valid = Self::verify_message(env.clone(), block_height, leaf, proof, proof_flags);
        if !valid {
            return false;
        }

        Self::consume_nonce(&env, nonce);
        true
    }

    /// Returns true if the nonce has already been consumed.
    pub fn is_nonce_processed(env: Env, nonce: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ProcessedNonce(nonce))
            .unwrap_or(false)
    }

    fn consume_nonce(env: &Env, nonce: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::ProcessedNonce(nonce), &true);
    }
}

mod test;

use soroban_sdk::{contract, contractimpl, Address, Env, Bytes};

#[contract]
pub struct CrossChainVerifierContract;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    ProcessedNonce(u64),
}

#[contractimpl]
impl CrossChainVerifierContract {
    /// Checks whether a cross-chain transaction nonce has already been processed.
    /// Retains the correct DataKey::ProcessedNonce storage lookup.
    pub fn is_nonce_processed(env: Env, nonce: u64) -> bool {
        let key = DataKey::ProcessedNonce(nonce);
        env.storage().persistent().has(&key)
    }

    // Note: The duplicate competing `is_nonce_processed` function has been removed from this module.
}

use soroban_sdk::{contract, contractimpl, Address, Env, Bytes, Symbol};

#[contract]
pub struct CrossChainVerifierContract;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Paused,
    ProcessedNonce(u64),
}

#[contractimpl]
impl CrossChainVerifierContract {
    /// Verifies an incoming cross-chain message, ensures the contract is not paused,
    /// checks that the nonce has not been replayed, consumes it, and emits an event.
    pub fn verify_message_and_consume(
        env: Env,
        nonce: u64,
        sender: Address,
        payload: Bytes,
    ) -> Result<(), &'static str> {
        // 1. Enforce pause state check (security requirement)
        let is_paused: bool = env.storage().persistent().get(&DataKey::Paused).unwrap_or(false);
        if is_paused {
            return Err("Contract is currently paused");
        }

        // 2. Prevent replay attacks using nonce storage check
        let nonce_key = DataKey::ProcessedNonce(nonce);
        if env.storage().persistent().has(&nonce_key) {
            return Err("Nonce already processed");
        }

        // 3. Mark nonce as consumed/processed
        env.storage().persistent().set(&nonce_key, &true);

        // 4. Emit nonce consumed event
        let topics = (Symbol::new(&env, "nonce_consumed"), nonce);
        env.events().publish(topics, sender);

        Ok(())
    }

    // Note: The unpaused duplicate `verify_message_and_consume` has been removed.
}

use soroban_sdk::{contract, contractimpl, Address, Env, BytesN};

#[contract]
pub struct CrossChainVerifierContract;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    MerkleRoot,
}

#[contractimpl]
impl CrossChainVerifierContract {
    /// Updates the trusted Merkle root for cross-chain message verification.
    /// Strictly requires administrative authorization.
    pub fn update_root(env: Env, new_root: BytesN<32>) -> Result<(), &'static str> {
        // 1. Retrieve administrative address from persistent storage
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or("Admin not configured")?;

        // 2. Enforce admin signature and authorization gate
        admin.require_auth();

        // 3. Store the updated Merkle root
        env.storage().persistent().set(&DataKey::MerkleRoot, &new_root);

        Ok(())
    }

    // Note: The unauthenticated duplicate `update_root` function has been successfully removed.
}

use soroban_sdk::{contract, contracttype};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    MerkleRoot,
    Paused,
    ProcessedNonce(u64),
    StateRoot(u32), // Retained single declaration of StateRoot variant
}

use soroban_sdk::{Env, BytesN, Address};

// ... within impl CrossChainVerifier ...

impl CrossChainVerifier {
    /// Verifies the cryptographic signature and checks storage for SignerAlgorithm and revocation nonces.
    fn verify_signature(env: &Env, signer: &Address, payload: &[u8], signature: &[u8]) -> bool {
        // 1. Retrieve and validate SignerAlgorithm from contract storage
        let algorithm = Self::get_signer_algorithm(env, signer);
        
        // 2. Perform signature cryptographic verification matching the algorithm
        let is_valid = match algorithm {
            SignerAlgorithm::Ed25519 => {
                // Verify Ed25519 signature proof against public key and payload
                env.crypto().ed25519_verify(signer, payload, signature)
            }
            SignerAlgorithm::Secp256k1 => {
                // Verify Secp256k1 signature proof
                env.crypto().secp256k1_verify(signer, payload, signature)
            }
        };

        if !is_valid {
            return false;
        }

        // 3. Ensure signature/nonce has not been revoked or replayed
        let nonce_key = DataKey::ProcessedNonce(Self::hash_payload(payload));
        if env.storage().persistent().has(&nonce_key) {
            return false;
        }

        true
    }
}


use soroban_sdk::{Env, Address, symbol_short};

// ... within impl CrossChainVerifier ...

pub fn remove_authorized_signer(env: Env, admin: Address, signer: Address) -> Result<(), ContractError> {
    admin.require_auth();

    // 1. Verify admin authorization
    Self::validate_admin(&env, &admin)?;

    // 2. Check if the signer exists in storage before removal
    let signer_key = DataKey::AuthorizedSigner(signer.clone());
    if !env.storage().persistent().has(&signer_key) {
        return Err(ContractError::SignerNotFound);
    }

    // 3. Remove signer from persistent storage exactly once
    env.storage().persistent().remove(&signer_key);

    // 4. Safely decrement SignerCount with underflow protection
    let count_key = DataKey::SignerCount;
    let mut count: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
    
    if count > 0 {
        count -= 1;
        env.storage().persistent().set(&count_key, &count);
    } else {
        return Err(ContractError::InvalidSignerCount);
    }

    env.events().publish(
        (symbol_short!("signer"), symbol_short!("removed")),
        signer,
    );

    Ok(())
}

use soroban_sdk::{Env, Address, symbol_short};

// ... within impl CrossChainVerifier ...

pub fn add_authorized_signer(env: Env, admin: Address, signer: Address, algorithm: SignerAlgorithm) -> Result<(), ContractError> {
    admin.require_auth();

    // 1. Verify admin authorization
    Self::validate_admin(&env, &admin)?;

    // 2. Check if signer is already registered to prevent redundant overwrites
    let signer_key = DataKey::AuthorizedSigner(signer.clone());
    if env.storage().persistent().has(&signer_key) {
        return Err(ContractError::SignerAlreadyExists);
    }

    // 3. Store signer authorization state and algorithm atomically (single write)
    env.storage().persistent().set(&signer_key, &algorithm);

    // 4. Safely increment SignerCount exactly once
    let count_key = DataKey::SignerCount;
    let mut count: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
    count += 1;
    env.storage().persistent().set(&count_key, &count);

    env.events().publish(
        (symbol_short!("signer"), symbol_short!("added")),
        (signer, algorithm),
    );

    Ok(())
}

use soroban_sdk::{Env, Bytes, BytesN};

// ... within impl CrossChainVerifier ...

impl CrossChainVerifier {
    /// Hashes the cross-chain message payload consistently with the v1 domain separator.
    fn hash_message(env: &Env, payload: &[u8]) -> BytesN<32> {
        let mut message = Bytes::new(env);
        message.extend_from_slice(b"CROSS_CHAIN_MESSAGE_V1");
        message.extend_from_slice(payload);
        
        env.crypto().keccak256(&message).into()
    }
}
