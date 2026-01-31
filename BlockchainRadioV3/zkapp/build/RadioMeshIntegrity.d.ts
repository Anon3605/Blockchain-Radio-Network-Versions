import { Field, SmartContract, State, PublicKey, Signature, UInt64 } from 'o1js';
declare const RadioPacket_base: (new (value: {
    uid: import("o1js/dist/node/lib/provable/field").Field;
    sourceId: import("o1js/dist/node/lib/provable/field").Field;
    dataHash: import("o1js/dist/node/lib/provable/field").Field;
    timestamp: UInt64;
}) => {
    uid: import("o1js/dist/node/lib/provable/field").Field;
    sourceId: import("o1js/dist/node/lib/provable/field").Field;
    dataHash: import("o1js/dist/node/lib/provable/field").Field;
    timestamp: UInt64;
}) & {
    _isStruct: true;
} & Omit<import("o1js/dist/node/lib/provable/types/provable-intf").Provable<{
    uid: import("o1js/dist/node/lib/provable/field").Field;
    sourceId: import("o1js/dist/node/lib/provable/field").Field;
    dataHash: import("o1js/dist/node/lib/provable/field").Field;
    timestamp: UInt64;
}, {
    uid: bigint;
    sourceId: bigint;
    dataHash: bigint;
    timestamp: bigint;
}>, "fromFields"> & {
    fromFields: (fields: import("o1js/dist/node/lib/provable/field").Field[]) => {
        uid: import("o1js/dist/node/lib/provable/field").Field;
        sourceId: import("o1js/dist/node/lib/provable/field").Field;
        dataHash: import("o1js/dist/node/lib/provable/field").Field;
        timestamp: UInt64;
    };
} & {
    fromValue: (value: {
        uid: string | number | bigint | import("o1js/dist/node/lib/provable/field").Field;
        sourceId: string | number | bigint | import("o1js/dist/node/lib/provable/field").Field;
        dataHash: string | number | bigint | import("o1js/dist/node/lib/provable/field").Field;
        timestamp: bigint | UInt64;
    }) => {
        uid: import("o1js/dist/node/lib/provable/field").Field;
        sourceId: import("o1js/dist/node/lib/provable/field").Field;
        dataHash: import("o1js/dist/node/lib/provable/field").Field;
        timestamp: UInt64;
    };
    toInput: (x: {
        uid: import("o1js/dist/node/lib/provable/field").Field;
        sourceId: import("o1js/dist/node/lib/provable/field").Field;
        dataHash: import("o1js/dist/node/lib/provable/field").Field;
        timestamp: UInt64;
    }) => {
        fields?: Field[] | undefined;
        packed?: [Field, number][] | undefined;
    };
    toJSON: (x: {
        uid: import("o1js/dist/node/lib/provable/field").Field;
        sourceId: import("o1js/dist/node/lib/provable/field").Field;
        dataHash: import("o1js/dist/node/lib/provable/field").Field;
        timestamp: UInt64;
    }) => {
        uid: string;
        sourceId: string;
        dataHash: string;
        timestamp: string;
    };
    fromJSON: (x: {
        uid: string;
        sourceId: string;
        dataHash: string;
        timestamp: string;
    }) => {
        uid: import("o1js/dist/node/lib/provable/field").Field;
        sourceId: import("o1js/dist/node/lib/provable/field").Field;
        dataHash: import("o1js/dist/node/lib/provable/field").Field;
        timestamp: UInt64;
    };
    empty: () => {
        uid: import("o1js/dist/node/lib/provable/field").Field;
        sourceId: import("o1js/dist/node/lib/provable/field").Field;
        dataHash: import("o1js/dist/node/lib/provable/field").Field;
        timestamp: UInt64;
    };
};
/**
 * RadioPacket - Represents a packet in the radio mesh network
 */
export declare class RadioPacket extends RadioPacket_base {
    /**
     * Create a RadioPacket from raw data
     */
    static fromData(uid: number, sourceId: number, data: string, timestamp: number): RadioPacket;
    /**
     * Compute a commitment to this packet
     * This is what gets signed by the sender
     */
    hash(): Field;
}
/**
 * RadioMeshIntegrity - Smart Contract for verifying data integrity in radio mesh
 *
 * This contract proves:
 * 1. The data hasn't been tampered with (hash verification)
 * 2. The packet is authentic (signature verification)
 * 3. The packet is unique (UID tracking)
 * 4. The packet is recent (timestamp validation)
 */
export declare class RadioMeshIntegrity extends SmartContract {
    lastVerifiedUid: State<import("o1js/dist/node/lib/provable/field").Field>;
    totalVerified: State<import("o1js/dist/node/lib/provable/field").Field>;
    authorizedSendersRoot: State<import("o1js/dist/node/lib/provable/field").Field>;
    init(): void;
    /**
     * Main verification method - proves a packet's integrity
     *
     * @param packet - The packet to verify
     * @param originalData - The original data content
     * @param senderPublicKey - Public key of the sender
     * @param senderSignature - Signature from sender
     */
    verifyPacketIntegrity(packet: RadioPacket, originalData: Field, senderPublicKey: PublicKey, senderSignature: Signature): Promise<void>;
    /**
     * Lightweight verification - doesn't update state
     * Used by intermediate repeaters for faster verification
     * Note: @method in o1js must return void, so we use assertions
     */
    quickVerify(packet: RadioPacket, originalData: Field, senderPublicKey: PublicKey, senderSignature: Signature): Promise<void>;
}
export {};
