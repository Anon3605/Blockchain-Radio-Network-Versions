#!/usr/bin/env node
/**
 * generate_proof.ts - Generate ZK proof for packet integrity
 */
import { Field, Mina, PrivateKey, Signature, Poseidon, UInt64, AccountUpdate } from 'o1js';
import { RadioPacket, RadioMeshIntegrity } from './RadioMeshIntegrity.js';
/**
 * Generate a ZK proof for a packet
 */
async function generateProof(packetData) {
    console.error('[PROOF] Starting proof generation...');
    const startTime = Date.now();
    // Parse input
    const { uid, sid, data, timestamp } = packetData;
    // Set up local blockchain for proof generation
    const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
    Mina.setActiveInstance(Local);
    // Get test accounts (in production, use real keys)
    const deployerAccount = Local.testAccounts[0];
    const senderAccount = Local.testAccounts[1];
    const senderKey = senderAccount.key;
    console.error('[PROOF] Compiling contract...');
    const compileStart = Date.now();
    await RadioMeshIntegrity.compile();
    console.error(`[PROOF] Compiled in ${Date.now() - compileStart}ms`);
    // Create zkApp instance
    const zkAppPrivateKey = PrivateKey.random();
    const zkAppAddress = zkAppPrivateKey.toPublicKey();
    const zkApp = new RadioMeshIntegrity(zkAppAddress);
    // DEPLOY THE ZKAPP FIRST
    console.error('[PROOF] Deploying zkApp...');
    const deployTxn = await Mina.transaction(deployerAccount, async () => {
        AccountUpdate.fundNewAccount(deployerAccount);
        await zkApp.deploy();
    });
    await deployTxn.sign([deployerAccount.key, zkAppPrivateKey]).send();
    console.error('[PROOF] zkApp deployed successfully');
    // Create packet
    const dataBytes = new TextEncoder().encode(data);
    const dataHash = Poseidon.hash(Array.from(dataBytes.slice(0, 31)).map(b => Field(b)));
    const packet = new RadioPacket({
        uid: Field(uid),
        sourceId: Field(sid),
        dataHash: dataHash,
        timestamp: UInt64.from(timestamp),
    });
    // Create signature
    const packetHash = packet.hash();
    const signature = Signature.create(senderKey, [packetHash]);
    console.error('[PROOF] Generating proof...');
    const proofStart = Date.now();
    // Generate proof by calling the verification method
    const transaction = await Mina.transaction(deployerAccount, async () => {
        await zkApp.verifyPacketIntegrity(packet, dataHash, senderAccount, signature);
    });
    await transaction.prove();
    console.error(`[PROOF] Proof generated in ${Date.now() - proofStart}ms`);
    // Sign and send transaction
    await transaction.sign([deployerAccount.key]).send();
    // Extract the proof
    const proof = transaction.toPretty();
    const totalTime = Date.now() - startTime;
    console.error(`[PROOF] Total time: ${totalTime}ms`);
    // Return proof data
    return {
        packet: {
            uid,
            sid,
            dataHash: dataHash.toString(),
            timestamp,
        },
        proof: proof,
        signature: signature.toBase58(),
        senderPublicKey: senderAccount.toBase58(),
        generationTime: totalTime,
        proofSize: JSON.stringify(proof).length,
    };
}
/**
 * Main execution
 */
async function main() {
    try {
        // Read input from command line or stdin
        let input;
        if (process.argv[2]) {
            input = JSON.parse(process.argv[2]);
        }
        else {
            // Read from stdin
            const chunks = [];
            for await (const chunk of process.stdin) {
                chunks.push(chunk);
            }
            input = JSON.parse(Buffer.concat(chunks).toString());
        }
        const result = await generateProof(input);
        // Output result as JSON to stdout
        console.log(JSON.stringify(result, null, 2));
        process.exit(0);
    }
    catch (error) {
        console.error('[ERROR]', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}
main();
//# sourceMappingURL=generate_proof.js.map