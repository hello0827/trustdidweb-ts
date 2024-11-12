export declare const createDID: (options: CreateDIDInterface) => Promise<{
    did: string;
    doc: any;
    meta: DIDResolutionMeta;
    log: DIDLog;
}>;
export declare const resolveDID: (log: DIDLog, options?: {
    versionNumber?: number;
    versionId?: string;
    versionTime?: Date;
    verificationMethod?: string;
}) => Promise<{
    did: string;
    doc: any;
    meta: DIDResolutionMeta;
}>;
export declare const updateDID: (options: UpdateDIDInterface) => Promise<{
    did: string;
    doc: any;
    meta: DIDResolutionMeta;
    log: DIDLog;
}>;
export declare const deactivateDID: (options: DeactivateDIDInterface) => Promise<{
    did: string;
    doc: any;
    meta: DIDResolutionMeta;
    log: DIDLog;
}>;
