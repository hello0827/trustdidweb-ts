import { resolveDID } from '../method.js';
import { getFileUrl } from '../utils.js';
export const getLatestDIDDoc = async ({ params: { id } }) => {
    try {
        const url = getFileUrl(id);
        const didLog = await (await fetch(url)).text();
        const logEntries = didLog.trim().split('\n').map(l => JSON.parse(l));
        const { did, doc, meta } = await resolveDID(logEntries);
        return { doc, meta };
    }
    catch (e) {
        console.error(e);
        throw new Error(`Failed to resolve DID`);
    }
};
export const getLogFileForSCID = async ({ params: { scid } }) => {
    return await Bun.file(`./src/routes/${scid}/did.jsonl`).text();
};
export const getLogFileForBase = async () => {
    return await Bun.file(`./src/routes/.well-known/did.jsonl`).text();
};
