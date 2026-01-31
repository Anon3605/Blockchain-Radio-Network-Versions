import {
  Field,
  SmartContract,
  state,
  State,
  method,
  PublicKey,
  Signature,
  Poseidon,
  Struct,
  UInt64,
} from 'o1js';

/**
 * SessionProof for Blockchain Radio V4
 * 
 * This ZK-SNARK contract proves:
 * 1. The node knows a private key corresponding to its public key
 * 2. The node commits to a session with specific parameters
 * 3. The commitment is binding (can't be changed later)
 * 
 * This proof is generated ONCE per session (~120s),
 * then all subsequent messages use fast HMAC authentication.
 */

/**
 * SessionData - Data committed to in the ZK proof
 */
export class SessionData extends Struct({
  nodeId: Field,           // Hash of node identifier
  publicKeyHash: Field,    // Hash of node's public key
  sessionNonce: Field,     // Random session nonce
  timestamp: UInt64,       // Session start time
  challenge: Field,        // Challenge from responder
}) {
  /**
   * Hash the session data for commitment
   */
  hash(): Field {
    return Poseidon.hash([
      this.nodeId,
      this.publicKeyHash,
      this.sessionNonce,
      this.timestamp.value,
      this.challenge,
    ]);
  }
}

/**
 * SessionProof zkApp
 * 
 * Proves identity and commits to session parameters without
 * revealing the private key.
 */
export class SessionProof extends SmartContract {
  // Track active sessions (commitment hashes)
  @state(Field) lastSessionCommitment = State<Field>();
  
  // Count of established sessions
  @state(Field) sessionCount = State<Field>();
  
  // Authorized nodes root (Merkle tree for production)
  @state(Field) authorizedNodesRoot = State<Field>();

  init() {
    super.init();
    this.lastSessionCommitment.set(Field(0));
    this.sessionCount.set(Field(0));
    this.authorizedNodesRoot.set(Field(0));
  }

  /**
   * Establish a new session
   * 
   * This is the main ZK proof - proves identity and creates commitment.
   * Called once per session establishment.
   */
  @method async establishSession(
    sessionData: SessionData,
    nodePublicKey: PublicKey,
    signature: Signature
  ) {
    // STEP 1: Verify the signature
    const sessionHash = sessionData.hash();
    
    const isValidSignature = signature.verify(
      nodePublicKey,
      [sessionHash]
    );
    isValidSignature.assertTrue('Invalid signature - identity verification failed');
    
    // STEP 2: Verify public key matches session data
    const publicKeyHash = Poseidon.hash(nodePublicKey.toFields());
    sessionData.publicKeyHash.assertEquals(
      publicKeyHash,
      'Public key hash mismatch'
    );
    
    // STEP 3: Verify timestamp is reasonable
    sessionData.timestamp.assertGreaterThan(
      UInt64.from(0),
      'Invalid timestamp'
    );
    
    // STEP 4: Update state
    this.lastSessionCommitment.set(sessionHash);
    
    const currentCount = this.sessionCount.getAndRequireEquals();
    this.sessionCount.set(currentCount.add(1));
  }

  /**
   * Verify an existing session commitment
   */
  @method async verifySession(
    sessionData: SessionData,
    commitment: Field
  ) {
    const computedHash = sessionData.hash();
    commitment.assertEquals(
      computedHash,
      'Session commitment mismatch - possible tampering'
    );
  }

  /**
   * Close a session
   */
  @method async closeSession(
    sessionData: SessionData,
    nodePublicKey: PublicKey,
    signature: Signature
  ) {
    const closeMessage = Poseidon.hash([
      sessionData.hash(),
      Field(0),
    ]);
    
    const isValid = signature.verify(nodePublicKey, [closeMessage]);
    isValid.assertTrue('Invalid signature for session closure');
    
    const lastCommitment = this.lastSessionCommitment.getAndRequireEquals();
    sessionData.hash().assertEquals(
      lastCommitment,
      'Can only close the last established session'
    );
    
    this.lastSessionCommitment.set(Field(0));
  }

  /**
   * Add an authorized node (admin function)
   */
  @method async addAuthorizedNode(
    newRoot: Field,
    adminSignature: Signature
  ) {
    this.authorizedNodesRoot.set(newRoot);
  }
}

/**
 * Helper: Create session data from parameters
 */
export function createSessionData(
  nodeId: string,
  publicKey: PublicKey,
  nonce: Field,
  timestamp: number,
  challenge: Field
): SessionData {
  const nodeIdHash = Poseidon.hash(
    Array.from(new TextEncoder().encode(nodeId).slice(0, 31)).map(b => Field(b))
  );
  
  const publicKeyHash = Poseidon.hash(publicKey.toFields());
  
  return new SessionData({
    nodeId: nodeIdHash,
    publicKeyHash: publicKeyHash,
    sessionNonce: nonce,
    timestamp: UInt64.from(timestamp),
    challenge: challenge,
  });
}
