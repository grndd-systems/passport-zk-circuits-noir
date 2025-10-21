// Type definitions for process_passport.js

// Re-exported ASN.1 utilities
export class Hex {
    static decode(input: string | Uint8Array): Uint8Array;
}

export class Base64 {
    static unarmor(input: string): Uint8Array;
}

export function decoded(input: string | Uint8Array): ASN1Node;

// Main types
export interface RSAPublicKey {
    n: string;
    exp: string;
}

export interface ECDSAPublicKey {
    x: string;
    y: string;
    param: string;
}

export interface RSASignature {
    n: string;
    salt: number | string;
}

export interface ECDSASignature {
    r: string;
    s: string;
}

export interface ASN1Node {
    name: string;
    content?: string;
    length?: number;
    sub?: ASN1Node[];
    dump?: string;
}

export interface ChunkedParams {
    ec_field_size: number;
    chunk_number: number;
    pk_chunked: bigint[];
    sig_chunked: bigint[];
    reduction: bigint[];
}

export interface PassportInputs {
    dg1: number[];
    dg15: number[];
    ec: number[];
    sa: number[];
    pk: bigint[];
    reduction: bigint[];
    sig: bigint[];
    sk_identity: bigint;
    icao_root: bigint;
    inclusion_branches: number[];
}

export interface PassportInputsFormatted {
    dg1: string;
    dg15: string;
    ec: string;
    sa: string;
    pk: string;
    reduction: string;
    sig: string;
    sk_identity: string;
    icao_root: string;
    inclusion_branches: string;
}

export interface CompileParams {
    dg1_len: number;
    dg15_len: number;
    ec_len: number;
    sa_len: number;
    n: number;
    ec_field_size: number;
    dg_hash_type: number;
    hash_type: number;
    sig_type: number;
    dg1_shift: number;
    dg15_shift: number;
    ec_shift: number;
    aa_sig_type: number;
    aa_shift: number;
}

/**
 * Computes a cryptographic hash of the input
 * @param outLen - Output length in bytes (20, 28, 32, 48, or 64)
 * @param input - Input data to hash
 * @returns Uint8Array containing the hash
 */
export function computeHash(outLen: number, input: Uint8Array | number[]): Uint8Array;

/**
 * Converts a bigint to an array of smaller bigints
 * @param n - Bit size of each chunk
 * @param k - Number of chunks
 * @param x - The bigint to split
 * @returns Array of bigints
 */
export function bigintToArray(n: number, k: number, x: bigint): bigint[];

/**
 * Computes Barrett reduction parameter
 * @param n_bits - Number of bits
 * @param n - Modulus
 * @returns Barrett reduction constant
 */
export function compute_barret_reduction(n_bits: number, n: bigint): bigint;

/**
 * Determines signature type based on public key and signature
 * @param pk - Public key (RSA or ECDSA)
 * @param sig - Signature
 * @param hashType - Hash type length
 * @returns Signature type identifier
 */
export function getSigType(
    pk: RSAPublicKey | ECDSAPublicKey,
    sig: RSASignature | ECDSASignature,
    hashType: string
): number;

/**
 * Converts hex string to byte array
 * @param hexString - Hex string to convert
 * @returns Array of bytes
 */
export function hexStringToBytes(hexString: string): number[];

/**
 * Reads and parses a JSON file synchronously
 * @param filePath - Path to JSON file
 * @returns Parsed JSON object
 */
export function readJsonFileSync(filePath: string): any;

/**
 * Gets the first OCTET_STRING from an ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns First OCTET_STRING node or undefined
 */
export function getFirstOctetString(asn1: ASN1Node): ASN1Node | undefined;

/**
 * Extracts encapsulated content from ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns Tuple of [content hex string, hash type]
 */
export function extract_encapsulated_content(asn1: ASN1Node): [string, number];

/**
 * Gets the shift offset for DG1 data
 * @param asn1 - ASN.1 node
 * @param dg1 - DG1 data
 * @param dgHashType - Hash type for DG
 * @returns Shift offset in bytes
 */
export function getDg1Shift(asn1: ASN1Node, dg1: Uint8Array | number[], dgHashType: number): number;

/**
 * Gets the shift offset for DG15 data
 * @param asn1 - ASN.1 node
 * @param dg15 - DG15 data
 * @param dgHashType - Hash type for DG
 * @returns Shift offset in bytes
 */
export function getDg15Shift(asn1: ASN1Node, dg15: Uint8Array | number[], dgHashType: number): number;

/**
 * Gets the shift offset for encapsulated content
 * @param asn1 - ASN.1 node
 * @param ec - Encapsulated content
 * @param hashType - Hash type
 * @returns Shift offset in bytes
 */
export function getEcShift(asn1: ASN1Node, ec: Uint8Array | number[], hashType: number): number;

/**
 * Gets EXPLICIT [0] element from ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns [0] element or null
 */
export function getZero(asn1: ASN1Node): ASN1Node | null;

/**
 * Extracts signed attributes from ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns Tuple of [signed attributes hex, hash type]
 */
export function extract_signed_atributes(asn1: ASN1Node): [string, number];

/**
 * Extracts signature from ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns RSA or ECDSA signature
 */
export function extract_signature(asn1: ASN1Node): RSASignature | ECDSASignature;

/**
 * Finds parent of last OCTET_STRING in ASN.1 tree
 * @param asn1 - ASN.1 node
 * @param parent - Parent node
 * @returns Tuple of [OCTET_STRING node, parent node]
 */
export function findParentOfLastOctetString(
    asn1: ASN1Node,
    parent?: ASN1Node | null
): [ASN1Node | null, ASN1Node | null];

/**
 * Gets ECDSA key location in ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns ASN.1 node containing ECDSA key or null
 */
export function get_ecdsa_key_location(asn1: ASN1Node): ASN1Node | null;

/**
 * Extracts ECDSA public key from ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns ECDSA public key
 */
export function extract_ecdsa_pubkey(asn1: ASN1Node): ECDSAPublicKey;

/**
 * Gets RSA key location in ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns ASN.1 node containing RSA key or null
 */
export function get_rsa_key_location(asn1: ASN1Node): ASN1Node | null;

/**
 * Extracts RSA public key from ASN.1 structure
 * @param asn1 - ASN.1 node
 * @returns RSA public key
 */
export function extract_rsa_pubkey(asn1: ASN1Node): RSAPublicKey;

/**
 * Extracts data from DG15
 * @param dg15 - DG15 data (base64 or hex string)
 * @returns Tuple of [public key, AA shift, AA signature type]
 */
export function extractFromDg15(
    dg15: string | null | undefined
): [RSAPublicKey | ECDSAPublicKey | 0, number, number | string];

/**
 * Gets chunked parameters for cryptographic operations
 * @param pk - Public key
 * @param sig - Signature
 * @returns Chunked parameters
 */
export function getChunkedParams(
    pk: RSAPublicKey | ECDSAPublicKey,
    sig: RSASignature | ECDSASignature
): ChunkedParams;

/**
 * Generates fake identity data for testing
 * @param ec - Encapsulated content
 * @param pk - Public key
 * @returns Tuple of [secret key, root hash, branches]
 */
export function getFakeIdenData(
    ec: Uint8Array | number[],
    pk: RSAPublicKey | ECDSAPublicKey
): [string, string, number[]];

/**
 * Formats passport inputs for Noir/TOML files
 * @param inputs - Passport inputs with numeric values
 * @returns Formatted inputs as strings
 */
export function formatInputsForNoir(inputs: PassportInputs): PassportInputsFormatted;

/**
 * Writes main.nr file for Noir
 * @param inputs - Passport inputs
 * @param params - Compile parameters
 * @param name - Circuit name
 */
export function writeMainToNoir(inputs: PassportInputs, params: CompileParams, name: string): void;

/**
 * Writes test_main.nr file for Noir
 * @param inputs - Passport inputs
 * @param params - Compile parameters
 * @param name - Test name
 */
export function writeTestToNoir(inputs: PassportInputs, params: CompileParams, name: string): void;

/**
 * Writes inputs to TOML file
 * @param inputs - Passport inputs
 */
export function writeToToml(inputs: PassportInputs): void;

/**
 * Result from preparePassportInputs function
 */
export interface PreparePassportResult {
    inputs: PassportInputs;
    compile_params: CompileParams;
    circuit_name: string;
}

/**
 * Prepare passport inputs from JSON data (without writing files)
 * Returns numeric values (bigints and number arrays) for easy use in your project
 * Use formatInputsForNoir() if you need string representations for Noir/TOML files
 *
 * @param json - Passport JSON data with dg1, dg15 (optional), and sod fields
 * @returns Object containing inputs (numeric values), compile_params, and circuit_name
 */
export function preparePassportInputs(json: {
    dg1?: string;
    dg15?: string;
    sod: string;
}): PreparePassportResult;

/**
 * Processes passport data and generates Noir circuit files
 * @param filePath - Path to passport JSON file
 */
export function processPassport(filePath: string): void;

/**
 * Poseidon hash function optimized for ZK circuits
 * @param inputs - Array of bigints to hash
 * @returns Hash result as bigint
 */
export function poseidon(inputs: bigint[]): bigint;
