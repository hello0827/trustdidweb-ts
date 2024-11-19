import fs from 'node:fs';
import * as base58btc from '@interop/base58-universal';
import { canonicalize } from 'json-canonicalize';
import { nanoid } from 'nanoid';
import { sha256 } from 'multiformats/hashes/sha2';
import { resolveDID } from './method.js';
import { join } from 'path';
export const readLogFromDisk = (path) => {
    return fs.readFileSync(path, 'utf8').trim().split('\n').map(l => JSON.parse(l));
};
export const writeLogToDisk = (path, log) => {
    fs.writeFileSync(path, JSON.stringify(log.shift()) + '\n');
    for (const entry of log) {
        fs.appendFileSync(path, JSON.stringify(entry) + '\n');
    }
};
export const writeVerificationMethodToEnv = (verificationMethod) => {
    const envFilePath = join(process.cwd(), '.env');
    const vmData = {
        id: verificationMethod.id,
        type: verificationMethod.type,
        controller: verificationMethod.controller || '',
        publicKeyMultibase: verificationMethod.publicKeyMultibase,
        secretKeyMultibase: verificationMethod.secretKeyMultibase || ''
    };
    try {
        let existingData = [];
        if (fs.existsSync(envFilePath)) {
            const envContent = fs.readFileSync(envFilePath, 'utf8');
            const match = envContent.match(/DID_VERIFICATION_METHODS=(.*)/);
            if (match && match[1]) {
                const decodedData = Buffer.from(match[1], 'base64').toString('utf8');
                existingData = JSON.parse(decodedData);
            }
        }
        existingData.push(vmData);
        const jsonData = JSON.stringify(existingData);
        const encodedData = Buffer.from(jsonData).toString('base64');
        const envContent = `DID_VERIFICATION_METHODS=${encodedData}\n`;
        fs.writeFileSync(envFilePath, envContent);
        console.log('Verification method written to .env file successfully.');
    }
    catch (error) {
        console.error('Error writing verification method to .env file:', error);
    }
};
export const clone = (input) => JSON.parse(JSON.stringify(input));
export const getBaseUrl = (id) => {
    const parts = id.split(':');
    if (!id.startsWith('did:tdw:') || parts.length < 4) {
        throw new Error(`${id} is not a valid did:tdw identifier`);
    }
    let domain = parts.slice(3).join('/');
    domain = domain.replace(/%2F/g, '/');
    domain = domain.replace(/%3A/g, ':');
    const protocol = domain.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${domain}`;
};
export const getFileUrl = (id) => {
    const baseUrl = getBaseUrl(id);
    const url = new URL(baseUrl);
    if (url.pathname !== '/') {
        return `${baseUrl}/did.jsonl`;
    }
    return `${baseUrl}/.well-known/did.jsonl`;
};
export const createDate = (created) => new Date(created ?? Date.now()).toISOString().slice(0, -5) + 'Z';
export function bytesToHex(bytes) {
    return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
}
export const createSCID = async (logEntryHash) => {
    return logEntryHash;
};
export const deriveHash = (input) => {
    const data = canonicalize(input);
    const encoder = new TextEncoder();
    return base58btc.encode(sha256.digest(encoder.encode(data)).bytes);
};
export const createDIDDoc = async (options) => {
    const { controller } = options;
    const { all } = normalizeVMs(options.verificationMethods, controller);
    return {
        doc: {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1"
            ],
            id: controller,
            controller,
            ...all
        }
    };
};
export const createVMID = (vm, did) => {
    return `${did ?? ''}#${vm.publicKeyMultibase?.slice(-8) || nanoid(8)}`;
};
export const normalizeVMs = (verificationMethod, did = null) => {
    if (!verificationMethod) {
        return {};
    }
    const all = {};
    const authentication = verificationMethod
        ?.filter(vm => vm.type === 'authentication').map(vm => createVMID(vm, did));
    if (authentication && authentication?.length > 0) {
        all.authentication = authentication;
    }
    const assertionMethod = verificationMethod
        ?.filter(vm => vm.type === 'assertionMethod').map(vm => createVMID(vm, did));
    if (assertionMethod && assertionMethod?.length > 0) {
        all.assertionMethod = assertionMethod;
    }
    const keyAgreement = verificationMethod
        ?.filter(vm => vm.type === 'keyAgreement').map(vm => createVMID(vm, did));
    if (keyAgreement && keyAgreement?.length > 0) {
        all.keyAgreement = keyAgreement;
    }
    const capabilityDelegation = verificationMethod
        ?.filter(vm => vm.type === 'capabilityDelegation').map(vm => createVMID(vm, did));
    if (capabilityDelegation && capabilityDelegation?.length > 0) {
        all.capabilityDelegation = capabilityDelegation;
    }
    const capabilityInvocation = verificationMethod
        ?.filter(vm => vm.type === 'capabilityInvocation').map(vm => createVMID(vm, did));
    if (capabilityInvocation && capabilityInvocation?.length > 0) {
        all.capabilityInvocation = capabilityInvocation;
    }
    if (verificationMethod && verificationMethod.length > 0) {
        all.verificationMethod = verificationMethod?.map(vm => ({
            id: createVMID(vm, did),
            ...(did ? { controller: vm.controller ?? did } : {}),
            type: 'Multikey',
            publicKeyMultibase: vm.publicKeyMultibase
        }));
    }
    return { all };
};
export const collectWitnessProofs = async (witnesses, log) => {
    const proofs = [];
    const timeout = (ms) => new Promise((_, reject) => setTimeout(() => reject(new Error('Request timed out')), ms));
    const collectProof = async (witness) => {
        const parts = witness.split(':');
        if (parts.length < 4) {
            throw new Error(`${witness} is not a valid did:tdw identifier`);
        }
        const witnessUrl = getBaseUrl(witness) + '/witness';
        try {
            const response = await Promise.race([
                fetch(witnessUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ log }),
                }),
                timeout(10000) // 10 second timeout
            ]);
            if (response.ok) {
                const data = await response.json();
                if (data.proof) {
                    proofs.push(data.proof);
                }
                else {
                    console.warn(`Witness ${witnessUrl} did not provide a valid proof`);
                }
            }
            else {
                console.warn(`Witness ${witnessUrl} responded with status: ${response.status}`);
            }
        }
        catch (error) {
            if (error.message === 'Request timed out') {
                console.error(`Request to witness ${witnessUrl} timed out`);
            }
            else {
                console.error(`Error collecting proof from witness ${witnessUrl}:`, error);
            }
        }
    };
    // Collect proofs from all witnesses concurrently
    await Promise.all(witnesses.map(collectProof));
    return proofs;
};
export const resolveVM = async (vm) => {
    try {
        if (vm.startsWith('did:key:')) {
            return { publicKeyMultibase: vm.split('did:key:')[1].split('#')[0] };
        }
        else if (vm.startsWith('did:tdw:')) {
            const url = getFileUrl(vm.split('#')[0]);
            const didLog = await (await fetch(url)).text();
            const logEntries = didLog.trim().split('\n').map(l => JSON.parse(l));
            const { doc } = await resolveDID(logEntries, { verificationMethod: vm });
            return findVerificationMethod(doc, vm);
        }
        throw new Error(`Verification method ${vm} not found`);
    }
    catch (e) {
        throw new Error(`Error resolving VM ${vm}`);
    }
};
export const findVerificationMethod = (doc, vmId) => {
    // Check in the verificationMethod array
    if (doc.verificationMethod && doc.verificationMethod.some((vm) => vm.id === vmId)) {
        return doc.verificationMethod.find((vm) => vm.id === vmId);
    }
    // Check in other verification method relationship arrays
    const vmRelationships = ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'];
    for (const relationship of vmRelationships) {
        if (doc[relationship]) {
            if (doc[relationship].some((item) => item.id === vmId)) {
                return doc[relationship].find((item) => item.id === vmId);
            }
        }
    }
    return null;
};
