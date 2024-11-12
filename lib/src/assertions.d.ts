export declare const documentStateIsValid: (doc: any, proofs: any[], updateKeys: string[], witnesses?: string[]) => Promise<boolean>;
export declare const hashChainValid: (derivedHash: string, logEntryHash: string) => boolean;
export declare const newKeysAreValid: (updateKeys: string[], previousNextKeyHashes: string[], nextKeyHashes: string[], previousPrerotation: boolean, prerotation: boolean) => boolean;
export declare const scidIsFromHash: (scid: string, hash: string) => Promise<boolean>;
