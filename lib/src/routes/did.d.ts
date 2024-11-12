export declare const getLatestDIDDoc: ({ params: { id } }: {
    params: {
        id: string;
    };
}) => Promise<{
    doc: any;
    meta: DIDResolutionMeta;
}>;
export declare const getLogFileForSCID: ({ params: { scid } }: {
    params: {
        scid: string;
    };
}) => Promise<string>;
export declare const getLogFileForBase: () => Promise<string>;
