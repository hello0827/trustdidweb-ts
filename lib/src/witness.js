import { createSigner } from './cryptography.js';
import { resolveDID } from './method.js';
// Parse the DID_VERIFICATION_METHODS environment variable
const verificationMethods = JSON.parse(Buffer.from(process.env.DID_VERIFICATION_METHODS || 'W10=', 'base64').toString('utf8'));
export async function createWitnessProof(log) {
    if (!Array.isArray(log) || log.length < 1) {
        return { error: 'Invalid log format' };
    }
    try {
        const { did, doc, meta } = await resolveDID(log);
        // Find the corresponding verification method with secret key
        const fullVM = verificationMethods.find((vm) => meta.witnesses.includes(vm.id.split('#')[0]));
        if (!fullVM || !fullVM.secretKeyMultibase) {
            return { error: 'Witness secret key not found' };
        }
        const logEntry = log[log.length - 1];
        const [versionId, timestamp, params, data] = logEntry;
        // Create a signer using the witness verification method
        const signer = createSigner({
            type: 'authentication',
            id: fullVM.id,
            controller: fullVM.controller ?? fullVM.id.split('#')[0],
            publicKeyMultibase: fullVM.publicKeyMultibase,
            secretKeyMultibase: fullVM.secretKeyMultibase
        }, false);
        // Sign the log entry
        const signedDoc = await signer(data.value, versionId);
        return {
            proof: signedDoc.proof
        };
    }
    catch (error) {
        console.error('Error in witness signing:', error);
        return { error: 'Failed to create witness proof' };
    }
}
