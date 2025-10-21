# passport-zk-circuits

[![npm version](https://badge.fury.io/js/passport-zk-circuits-noir-js.svg)](https://www.npmjs.com/package/passport-zk-circuits-noir-js)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

JavaScript utilities for processing passport data and generating Zero-Knowledge circuits with Noir. This package provides tools for extracting cryptographic data from electronic passports (eMRTD) and preparing inputs for ZK-SNARK verification circuits.

**npm package:** [`passport-zk-circuits-noir-js`](https://www.npmjs.com/package/passport-zk-circuits-noir-js)

## Features

- **ASN.1 Parsing**: Decode and extract data from passport Security Object Documents (SOD)
- **Multiple Signature Algorithms**: Support for RSA (2048/4096 bits) and ECDSA (various curves)
- **Hash Functions**: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- **RSA-PSS Support**: RSASSA-PSS with MGF1 and various salt lengths
- **ECDSA Curves**: Support for secp256r1, secp224r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
- **Poseidon Hashing**: Implementation of Poseidon hash function for ZK circuits
- **TypeScript Support**: Full TypeScript type definitions included
- **Data Group Extraction**: Extract and process DG1 (MRZ), DG15 (Active Authentication public key)

## Installation

```bash
npm install passport-zk-circuits-noir-js
```

Or with yarn:

```bash
yarn add passport-zk-circuits-noir-js
```

## Quick Start

```typescript
import { processPassport, preparePassportInputs } from 'passport-zk-circuits-noir-js';

// Option 1: Process passport and write files automatically
processPassport('./path/to/passport.json');

// Option 2: Prepare inputs without writing files (useful for custom processing)
const passportData = {
  dg1: "base64_or_hex_encoded_data",
  dg15: "base64_or_hex_encoded_data", // optional
  sod: "base64_or_hex_encoded_data"
};
const { inputs, compile_params, circuit_name } = preparePassportInputs(passportData);
// Use inputs and compile_params in your application
console.log(inputs.pk); // Public key chunks
console.log(compile_params.sig_type); // Signature type
```

## API Documentation

### Main Functions

#### `preparePassportInputs(json: Object): PreparePassportResult`

**NEW!** Prepare passport inputs from JSON data without writing files. This is useful when you want to process passport data in your own application without generating Noir files.

**Important:** The function now returns **native numeric values** (bigints and number arrays) instead of strings, making it much easier to use in your own projects without manual conversion.

```typescript
import { preparePassportInputs, formatInputsForNoir } from 'passport-zk-circuits';

const passportData = {
  dg1: "base64_encoded_dg1",
  dg15: "base64_encoded_dg15", // optional
  sod: "base64_encoded_sod"
};

const { inputs, compile_params, circuit_name } = preparePassportInputs(passportData);

// Access prepared inputs - now in native format!
console.log('DG1 bytes:', inputs.dg1);              // number[] - ready to use!
console.log('Public key chunks:', inputs.pk);       // bigint[] - no conversion needed!
console.log('Signature chunks:', inputs.sig);       // bigint[]
console.log('SK Identity:', inputs.sk_identity);    // bigint
console.log('ICAO Root:', inputs.icao_root);        // bigint
console.log('Signature type:', compile_params.sig_type); // number

// Use directly in your application - no string parsing required!
sendToBackend(inputs);
storeInDatabase(compile_params);

// If you need string format for Noir/TOML files:
const formattedInputs = formatInputsForNoir(inputs);
console.log('PK as string:', formattedInputs.pk); // "[0x123, 0x456, ...]"
```

**Returns:**
- `inputs`: Passport inputs in native format:
  - `dg1`, `dg15`, `ec`, `sa`: `number[]` (byte arrays)
  - `pk`, `reduction`, `sig`: `bigint[]` (chunked values)
  - `sk_identity`, `icao_root`: `bigint`
  - `inclusion_branches`: `number[]`
- `compile_params`: Circuit compilation parameters (lengths, types, shifts)
- `circuit_name`: Generated circuit identifier string

**Migration Note:** If you were previously parsing string values, you can now remove that code:
```typescript
// OLD (no longer needed):
const pkArray = JSON.parse(inputs.pk.replaceAll("0x", "").split(",").map(x => BigInt("0x" + x)));

// NEW (values are already native):
const pkArray = inputs.pk; // Already bigint[]
```

#### `processPassport(filePath: string): void`

Process passport data and generate Noir circuit files (`main.nr`, `test_main.nr`, `Prover.toml`). This function internally calls `preparePassportInputs` and writes the results to files.

```typescript
processPassport('./my-passport.json');
```

#### `formatInputsForNoir(inputs: PassportInputs): PassportInputsFormatted`

Converts passport inputs from native numeric format to string format for Noir/TOML files. Use this when you need to write inputs to files or when working with Noir circuits.

```typescript
import { preparePassportInputs, formatInputsForNoir } from 'passport-zk-circuits';

const { inputs } = preparePassportInputs(passportData);
const formatted = formatInputsForNoir(inputs);

console.log(formatted.pk);  // "[0x123, 0x456, ...]"
console.log(formatted.dg1); // "[1, 2, 3, ...]"
```

#### `computeHash(outLen: number, input: Uint8Array | number[]): Uint8Array`

Compute cryptographic hash with specified output length.

- `outLen`: Output length in bytes (20=SHA1, 28=SHA224, 32=SHA256, 48=SHA384, 64=SHA512)
- `input`: Data to hash

```typescript
const sha256 = computeHash(32, new Uint8Array([1, 2, 3, 4]));
```

#### `extractFromDg15(dg15: string): [PublicKey | 0, number, number]`

Extract Active Authentication public key from DG15 data group.

Returns: `[publicKey, aaShift, aaSigType]`

```typescript
const [aaPubKey, shift, sigType] = extractFromDg15(dg15Base64);
```

### ASN.1 Utilities

#### `extract_encapsulated_content(asn1: ASN1Node): [string, number]`

Extract encapsulated content from SOD structure.

```typescript
import { decoded } from 'passport-zk-circuits/asn1';

const asn1 = decoded(sodData);
const [ecHex, hashType] = extract_encapsulated_content(asn1);
```

#### `extract_signed_atributes(asn1: ASN1Node): [string, number]`

Extract signed attributes from SOD.

```typescript
const [saHex, hashType] = extract_signed_atributes(asn1);
```

#### `extract_signature(asn1: ASN1Node): RSASignature | ECDSASignature`

Extract signature from SOD (automatically detects RSA or ECDSA).

```typescript
const signature = extract_signature(asn1);
if ('r' in signature) {
  console.log('ECDSA signature:', signature.r, signature.s);
} else {
  console.log('RSA signature:', signature.n);
}
```

#### `extract_rsa_pubkey(asn1: ASN1Node): RSAPublicKey`

Extract RSA public key from SOD.

```typescript
const rsaPubKey = extract_rsa_pubkey(asn1);
console.log('Modulus:', rsaPubKey.n);
console.log('Exponent:', rsaPubKey.exp);
```

#### `extract_ecdsa_pubkey(asn1: ASN1Node): ECDSAPublicKey`

Extract ECDSA public key from SOD.

```typescript
const ecdsaPubKey = extract_ecdsa_pubkey(asn1);
console.log('x:', ecdsaPubKey.x);
console.log('y:', ecdsaPubKey.y);
console.log('curve:', ecdsaPubKey.param);
```

### Cryptographic Utilities

#### `bigintToArray(n: number, k: number, x: bigint): bigint[]`

Convert a bigint into an array of smaller bigints (used for chunking large numbers for circuits).

- `n`: Bit size of each chunk
- `k`: Number of chunks
- `x`: The bigint to split

```typescript
const chunks = bigintToArray(64, 32, 12345678901234567890n);
```

#### `compute_barret_reduction(n_bits: number, n: bigint): bigint`

Compute Barrett reduction parameter for modular arithmetic optimization.

```typescript
const reduction = compute_barret_reduction(2048, modulusN);
```

#### `poseidon(inputs: bigint[]): bigint`

Compute Poseidon hash (optimized for ZK circuits).

```typescript
// Import from main module
import { poseidon } from 'passport-zk-circuits';

const hash = poseidon([123n, 456n, 789n]);

// Or import from poseidon submodule
import { poseidon } from 'passport-zk-circuits/poseidon';
```

### Helper Functions

#### `getSigType(pk: PublicKey, sig: Signature, hashType: string): number`

Determine signature type identifier based on algorithm, key size, and hash function.

#### `hexStringToBytes(hexString: string): number[]`

Convert hex string to byte array.

#### `readJsonFileSync(filePath: string): any`

Read and parse JSON file synchronously.

## TypeScript Types

```typescript
// Passport inputs in native format (returned by preparePassportInputs)
interface PassportInputs {
  dg1: number[];              // DG1 data as byte array
  dg15: number[];             // DG15 data as byte array (empty if not present)
  ec: number[];               // Encapsulated content as byte array
  sa: number[];               // Signed attributes as byte array
  pk: bigint[];               // Public key chunks
  reduction: bigint[];        // Reduction parameter chunks
  sig: bigint[];              // Signature chunks
  sk_identity: bigint;        // Identity secret key
  icao_root: bigint;          // ICAO root
  inclusion_branches: number[]; // Inclusion branches
}

// Formatted inputs for Noir/TOML files (returned by formatInputsForNoir)
interface PassportInputsFormatted {
  dg1: string;                // "[1, 2, 3, ...]"
  dg15: string;               // "[1, 2, 3, ...]" or "[]"
  ec: string;                 // "[1, 2, 3, ...]"
  sa: string;                 // "[1, 2, 3, ...]"
  pk: string;                 // "[0x123, 0x456, ...]"
  reduction: string;          // "[0x123, 0x456, ...]"
  sig: string;                // "[0x123, 0x456, ...]"
  sk_identity: string;        // "0x123..."
  icao_root: string;          // "0x123..."
  inclusion_branches: string; // "[0, 0, 0, ...]"
}

interface RSAPublicKey {
  n: string;      // Modulus (hex)
  exp: string;    // Exponent (hex)
}

interface ECDSAPublicKey {
  x: string;      // X coordinate (hex)
  y: string;      // Y coordinate (hex)
  param: string;  // Curve parameter
}

interface RSASignature {
  n: string;           // Signature value (hex)
  salt: number | string; // Salt length (0 for PKCS#1 v1.5)
}

interface ECDSASignature {
  r: string;      // R value (hex)
  s: string;      // S value (hex)
}
```

## Supported Signature Types

### RSA PKCS#1 v1.5
- Type 1: RSA 2048 bits + SHA-256 + e=65537
- Type 2: RSA 4096 bits + SHA-256 + e=65537
- Type 3: RSA 2048 bits + SHA-1 + e=65537

### RSA-PSS
- Type 10: RSA 2048 bits MGF1(SHA-256) + SHA-256 + e=3 + salt=32
- Type 11: RSA 2048 bits MGF1(SHA-256) + SHA-256 + e=65537 + salt=32
- Type 12: RSA 2048 bits MGF1(SHA-256) + SHA-256 + e=65537 + salt=64
- Type 13: RSA 2048 bits MGF1(SHA-384) + SHA-384 + e=65537 + salt=48
- Type 14: RSA 3072 bits MGF1(SHA-256) + SHA-256 + e=65537 + salt=32

### ECDSA
- Type 20: secp256r1 + SHA-256
- Type 21: brainpoolP256r1 + SHA-256
- Type 22: brainpoolP320r1 + SHA-256
- Type 23: secp192r1 + SHA-1
- Type 24: secp224r1
- Type 25: brainpoolP384r1
- Type 26: brainpoolP512r1
- Type 27: secp521r1

## Passport JSON Format

The input JSON file should contain:

```json
{
  "dg1": "base64 or hex encoded DG1 data",
  "dg15": "base64 or hex encoded DG15 data (optional)",
  "sod": "base64 or hex encoded Security Object Document"
}
```

## Module Exports

```typescript
// Main module (includes everything)
import {
  processPassport,
  preparePassportInputs,
  formatInputsForNoir,  // NEW: Convert native values to strings
  computeHash,
  poseidon,
  extractFromDg15,
  decoded,        // ASN.1 decoder
  Hex,           // Hex utilities
  Base64,        // Base64 utilities
  // ... all other functions
} from 'passport-zk-circuits';

// Alternative: import from submodules
import { Hex, Base64, decoded } from 'passport-zk-circuits/asn1';
import { poseidon } from 'passport-zk-circuits/poseidon';
```

## Example: Full Workflow

```typescript
import {
  readJsonFileSync,
  extract_encapsulated_content,
  extract_signed_atributes,
  extract_signature,
  extract_rsa_pubkey,
  getSigType,
  getChunkedParams
} from 'passport-zk-circuits';
import { decoded } from 'passport-zk-circuits/asn1';

// Read passport data
const passportData = readJsonFileSync('./passport.json');

// Decode SOD
const asn1 = decoded(passportData.sod);

// Extract components
const [ecHex, dgHashType] = extract_encapsulated_content(asn1);
const [saHex, hashType] = extract_signed_atributes(asn1);
const signature = extract_signature(asn1);
const pubKey = extract_rsa_pubkey(asn1);

// Determine signature algorithm
const sigType = getSigType(pubKey, signature, hashType);
console.log('Signature type:', sigType);

// Prepare for circuit
const chunked = getChunkedParams(pubKey, signature);
console.log('Public key chunks:', chunked.pk_chunked);
```

## License

MIT

## Repository

This is a fork from [rarimo/passport-zk-circuits-noir](https://github.com/rarimo/passport-zk-circuits-noir).

- GitHub: https://github.com/grndd-systems/passport-zk-circuits-noir
- Issues: https://github.com/grndd-systems/passport-zk-circuits-noir/issues

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.

## Requirements

- Node.js >= 16.0.0
- ES Modules support
