export declare const createSigner: (vm: VerificationMethod, useStatic?: boolean) => (doc: any, challenge: string) => Promise<any>;
export declare const generateEd25519VerificationMethod: (purpose: 'authentication' | 'assertionMethod' | 'capabilityInvocation' | 'capabilityDelegation') => Promise<VerificationMethod>;
export declare const generateX25519VerificationMethod: (purpose: 'keyAgreement') => Promise<VerificationMethod>;
