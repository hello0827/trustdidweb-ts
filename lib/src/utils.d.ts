export declare const readLogFromDisk: (path: string) => DIDLog;
export declare const writeLogToDisk: (path: string, log: DIDLog) => void;
export declare const writeVerificationMethodToEnv: (verificationMethod: VerificationMethod) => void;
export declare const clone: (input: any) => any;
export declare const getBaseUrl: (id: string) => string;
export declare const getFileUrl: (id: string) => string;
export declare const createDate: (created?: Date | string) => string;
export declare function bytesToHex(bytes: Uint8Array): string;
export declare const createSCID: (logEntryHash: string) => Promise<string>;
export declare const deriveHash: (input: any) => string;
export declare const createDIDDoc: (options: CreateDIDInterface) => Promise<{
    doc: DIDDoc;
}>;
export declare const createVMID: (vm: VerificationMethod, did: string | null) => string;
export declare const normalizeVMs: (verificationMethod: VerificationMethod[] | undefined, did?: string | null) => {
    all?: undefined;
} | {
    all: any;
};
export declare const collectWitnessProofs: (witnesses: string[], log: DIDLog) => Promise<DataIntegrityProof[]>;
export declare const resolveVM: (vm: string) => Promise<VerificationMethod | {
    publicKeyMultibase: string;
} | null>;
export declare const findVerificationMethod: (doc: any, vmId: string) => VerificationMethod | null;
