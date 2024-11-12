import { createDID, resolveDID, updateDID, deactivateDID } from './method.js';
import { createSigner, generateEd25519VerificationMethod } from './cryptography.js';
import { getFileUrl, readLogFromDisk, writeLogToDisk, writeVerificationMethodToEnv } from './utils.js';
const usage = `
Usage: bun run cli [command] [options]

Commands:
  create     Create a new DID
  resolve    Resolve a DID
  update     Update an existing DID
  deactivate Deactivate an existing DID

Options:
  --domain [domain]         Domain for the DID (required for create)
  --log [file]              Path to the DID log file (required for resolve, update, deactivate)
  --output [file]           Path to save the updated DID log (optional for create, update, deactivate)
  --portable                Make the DID portable (optional for create)
  --prerotation             Enable pre-rotation (optional for create and update)
  --witness [witness]       Add a witness (can be used multiple times)
  --witness-threshold [n]   Set witness threshold (optional, defaults to number of witnesses)
  --service [service]       Add a service (format: type,endpoint) (can be used multiple times)
  --add-vm [type]           Add a verification method (type can be authentication, assertionMethod, keyAgreement, capabilityInvocation, capabilityDelegation)
  --also-known-as [alias]   Add an alsoKnownAs alias (can be used multiple times)

Examples:
  bun run cli create --domain example.com --portable --witness did:example:witness1 --witness did:example:witness2
  bun run cli resolve --did did:tdw:123456:example.com
  bun run cli update --log ./did.jsonl --output ./updated-did.jsonl --add-vm keyAgreement --service LinkedDomains,https://example.com
  bun run cli deactivate --log ./did.jsonl --output ./deactivated-did.jsonl
`;
async function main() {
    const args = Bun.argv.slice(2);
    const command = args[0];
    if (!command) {
        console.log(usage);
        process.exit(1);
    }
    try {
        switch (command) {
            case 'create':
                await handleCreate(args.slice(1));
                break;
            case 'resolve':
                await handleResolve(args.slice(1));
                break;
            case 'update':
                await handleUpdate(args.slice(1));
                break;
            case 'deactivate':
                await handleDeactivate(args.slice(1));
                break;
            default:
                console.log(`Unknown command: ${command}`);
                console.log(usage);
                process.exit(1);
        }
    }
    catch (error) {
        console.error('An error occurred:', error);
        process.exit(1);
    }
}
async function handleCreate(args) {
    const options = parseOptions(args);
    const domain = options['domain'];
    const output = options['output'];
    const portable = options['portable'] !== undefined;
    const prerotation = options['prerotation'] !== undefined;
    const witnesses = options['witness'];
    const witnessThreshold = options['witness-threshold'] ? parseInt(options['witness-threshold']) : witnesses?.length ?? 0;
    if (!domain) {
        console.error('Domain is required for create command');
        process.exit(1);
    }
    const authKey = await generateEd25519VerificationMethod('authentication');
    const { did, doc, meta, log } = await createDID({
        domain,
        signer: createSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase],
        verificationMethods: [authKey],
        portable,
        prerotation,
        witnesses,
        witnessThreshold,
    });
    console.log('Created DID:', did);
    // console.log('DID Document:', JSON.stringify(doc, null, 2));
    // console.log('Meta:', JSON.stringify(meta, null, 2));
    // console.log('DID Log:', JSON.stringify(log, null, 2));
    if (output) {
        writeLogToDisk(output, log);
        console.log(`DID log written to ${output}`);
        writeVerificationMethodToEnv({ ...authKey, controller: did, id: `${did}#${authKey.publicKeyMultibase?.slice(-8)}` });
        console.log(`DID verification method saved to env`);
    }
}
async function handleResolve(args) {
    const options = parseOptions(args);
    const didIdentifier = options['did'];
    if (!didIdentifier) {
        console.error('DID identifier is required for resolve command');
        process.exit(1);
    }
    try {
        const log = await fetchLogFromIdentifier(didIdentifier);
        const { did, doc, meta } = await resolveDID(log);
        console.log('Resolved DID:', did);
        console.log('DID Document:', JSON.stringify(doc, null, 2));
        console.log('Metadata:', meta);
    }
    catch (error) {
        console.error('Error resolving DID:', error);
        process.exit(1);
    }
}
async function fetchLogFromIdentifier(identifier) {
    try {
        const url = getFileUrl(identifier);
        console.log(url, identifier);
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const text = await response.text();
        return text.trim().split('\n').map(line => JSON.parse(line));
    }
    catch (error) {
        console.error('Error fetching DID log:', error);
        throw error;
    }
}
async function handleUpdate(args) {
    const options = parseOptions(args);
    const logFile = options['log'];
    const output = options['output'];
    const prerotation = options['prerotation'] !== undefined;
    const witnesses = options['witness'];
    const witnessThreshold = options['witness-threshold'] ? parseInt(options['witness-threshold']) : undefined;
    const services = options['service'] ? parseServices(options['service']) : undefined;
    const addVm = options['add-vm'];
    const alsoKnownAs = options['also-known-as'];
    if (!logFile) {
        console.error('Log file is required for update command');
        process.exit(1);
    }
    const log = readLogFromDisk(logFile);
    const authKey = await generateEd25519VerificationMethod('authentication');
    const verificationMethods = [
        authKey,
        ...(addVm?.map(type => ({
            type,
            publicKeyMultibase: authKey.publicKeyMultibase,
        })) || [])
    ];
    const { did, doc, meta, log: updatedLog } = await updateDID({
        log,
        signer: createSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase],
        verificationMethods,
        prerotation,
        witnesses,
        witnessThreshold,
        services,
        alsoKnownAs,
    });
    console.log('Updated DID:', did);
    console.log('Updated DID Document:', JSON.stringify(doc, null, 2));
    console.log('Updated Metadata:', meta);
    if (output) {
        writeLogToDisk(output, updatedLog);
        console.log(`Updated DID log written to ${output}`);
    }
}
async function handleDeactivate(args) {
    const options = parseOptions(args);
    const logFile = options['log'];
    const output = options['output'];
    if (!logFile) {
        console.error('Log file is required for deactivate command');
        process.exit(1);
    }
    const log = readLogFromDisk(logFile);
    const authKey = await generateEd25519VerificationMethod('authentication');
    const { did, doc, meta, log: deactivatedLog } = await deactivateDID({
        log,
        signer: createSigner(authKey),
    });
    console.log('Deactivated DID:', did);
    console.log('Deactivated DID Document:', JSON.stringify(doc, null, 2));
    console.log('Deactivated Metadata:', meta);
    if (output) {
        writeLogToDisk(output, deactivatedLog);
        console.log(`Deactivated DID log written to ${output}`);
    }
}
function parseOptions(args) {
    const options = {};
    for (let i = 0; i < args.length; i++) {
        if (args[i].startsWith('--')) {
            const key = args[i].slice(2);
            if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
                if (key === 'witness' || key === 'service' || key === 'also-known-as') {
                    options[key] = options[key] || [];
                    options[key].push(args[++i]);
                }
                else if (key === 'add-vm') {
                    options[key] = options[key] || [];
                    const value = args[++i];
                    if (isValidVerificationMethodType(value)) {
                        options[key].push(value);
                    }
                    else {
                        console.error(`Invalid verification method type: ${value}`);
                        process.exit(1);
                    }
                }
                else {
                    options[key] = args[++i];
                }
            }
            else {
                options[key] = '';
            }
        }
    }
    return options;
}
// Add this function to validate VerificationMethodType
function isValidVerificationMethodType(type) {
    return ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'].includes(type);
}
function parseServices(services) {
    return services.map(service => {
        const [type, serviceEndpoint] = service.split(',');
        return { type, serviceEndpoint };
    });
}
main();
