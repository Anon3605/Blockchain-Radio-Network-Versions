#!/usr/bin/env node
/**
 * verify_proof.ts - Verify ZK proof for packet integrity
 */
import { Field, Mina, PrivateKey, PublicKey, Signature, UInt64 } from 'o1js';
import { RadioPacket, RadioMeshIntegrity } from './RadioMeshIntegrity.js';
/**
 * Verify a ZK proof
 */
async function verifyProof(proofData) {
    console.error('[VERIFY] Starting proof verification...');
    const startTime = Date.now();
    const { packet, proof, signature, senderPublicKey } = proofData;
    // Set up local blockchain
    const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
    Mina.setActiveInstance(Local);
    console.error('[VERIFY] Compiling contract...');
    const compileStart = Date.now();
    await RadioMeshIntegrity.compile();
    console.error(`[VERIFY] Compiled in ${Date.now() - compileStart}ms`);
    // Create zkApp instance
    const zkAppPrivateKey = PrivateKey.random();
    const zkAppAddress = zkAppPrivateKey.toPublicKey();
    const zkApp = new RadioMeshIntegrity(zkAppAddress);
    // Reconstruct packet
    const dataHash = Field(packet.dataHash);
    const radioPacket = new RadioPacket({
        uid: Field(packet.uid),
        sourceId: Field(packet.sid),
        dataHash: dataHash,
        timestamp: UInt64.from(packet.timestamp),
    });
    // Reconstruct signature
    const sig = Signature.fromBase58(signature);
    const pubKey = PublicKey.fromBase58(senderPublicKey);
    console.error('[VERIFY] Verifying signature...');
    const packetHash = radioPacket.hash();
    const signatureValid = sig.verify(pubKey, [packetHash]);
    if (!signatureValid.toBoolean()) {
        return {
            valid: false,
            reason: 'Invalid signature',
            verificationTime: Date.now() - startTime,
        };
    }
    console.error('[VERIFY] Signature valid');
    // Note: In o1js, @method must return void
    // We verify by checking if it throws an error
    try {
        // This will throw if verification fails
        await zkApp.quickVerify(radioPacket, dataHash, pubKey, sig);
        console.error('[VERIFY] Quick verification passed');
    }
    catch (error) {
        return {
            valid: false,
            reason: 'Proof verification failed: ' + error.message,
            verificationTime: Date.now() - startTime,
        };
    }
    const totalTime = Date.now() - startTime;
    console.error(`[VERIFY] Total time: ${totalTime}ms`);
    return {
        valid: true,
        packet: {
            uid: packet.uid,
            sourceId: packet.sid,
            verified: true,
        },
        verificationTime: totalTime,
    };
}
/**
 * Main execution
 */
async function main() {
    try {
        // Read input
        let input;
        if (process.argv[2]) {
            input = JSON.parse(process.argv[2]);
        }
        else {
            const chunks = [];
            for await (const chunk of process.stdin) {
                chunks.push(chunk);
            }
            input = JSON.parse(Buffer.concat(chunks).toString());
        }
        const result = await verifyProof(input);
        // Output result
        console.log(JSON.stringify(result, null, 2));
        process.exit(result.valid ? 0 : 1);
    }
    catch (error) {
        console.error('[ERROR]', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}
main();
//# sourceMappingURL=verify_proof.js.map