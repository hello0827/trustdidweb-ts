import { createSigner, generateEd25519VerificationMethod, generateX25519VerificationMethod } from "../lib/src/cryptography.js";
import { createDID, deactivateDID, resolveDID, updateDID } from "../lib/src/method.js";
import { createVMID, deriveHash } from "../lib/src/utils.js";

async function main(){
    const currentAuthKey = await generateEd25519VerificationMethod('authentication');
    const nextAuthKey = await generateEd25519VerificationMethod('authentication');
    const nextNextAuthKey = await generateEd25519VerificationMethod('authentication');
    const nextKeyHash = await deriveHash(nextAuthKey.publicKeyMultibase);
    const nextNextKeyHash = await deriveHash(nextNextAuthKey.publicKeyMultibase);

    const {did: v1DID, doc: v1Doc, meta: v1meta, log: v1Log} = await createDID({
        domain: 'example.com:dids:user',
        signer: createSigner(currentAuthKey),
        updateKeys: [currentAuthKey.publicKeyMultibase],
        portable: true,
        prerotation: true,
        nextKeyHashes: [nextKeyHash],
        verificationMethods: [
        currentAuthKey
        ]});

    // Resolve DID document
    //console.log(await resolveDID(v1Log));
    
    console.dir(v1Log,{depth:null});
    console.dir(v1meta,{depth:null});
    console.dir(v1DID,{depth:null});
    console.dir(v1Doc,{depth:null});
    //console.dir(await resolveDID(v1Log),{depth:null});
    console.log("======v2======");

    const {did: v2DID, doc: v2Doc, meta: v2meta, log: v2Log} =
        await updateDID({
            log: v1Log,
            signer: createSigner(currentAuthKey),
            updateKeys: [nextAuthKey.publicKeyMultibase],
            portable: true,
            prerotation: true,
            nextKeyHashes: [nextNextKeyHash],
            verificationMethods: [
                nextAuthKey
            ]
        });
        console.dir(v2Log,{depth:null});
        await console.log("======resolve======");
     console.log(await resolveDID(v2Log));

    console.dir(v2Log,{depth:null});
    console.dir(v2meta,{depth:null});
    console.dir(v2DID,{depth:null});
    console.dir(v2Doc,{depth:null});

    console.log("======deactivate======");
    const {did: deactivatedDID, doc: deactivatedDoc, mata: deactivatedMeta, log: deactivatedLog} =
    await deactivateDID({
      log: v2Log,
      signer: createSigner(nextAuthKey)
    });
    console.dir(deactivatedMeta,{depth:null});
    console.dir(deactivatedLog,{depth:null});
    console.dir(deactivatedDID,{depth:null});
    console.dir(deactivatedDoc,{depth:null});

}

await main();