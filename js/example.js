// Example: Using preparePassportInputs in your application

import {
  preparePassportInputs,
  readJsonFileSync,
  poseidon,
  decoded,
  Hex,
  Base64
} from './process_passport.js';

console.log('=== Example 1: Using preparePassportInputs ===\n');

// Option 1: If you already have passport JSON data
const passportData = {
  dg1: "base64_or_hex_encoded_dg1",
  dg15: "base64_or_hex_encoded_dg15", // optional
  sod: "base64_or_hex_encoded_sod"
};

// Prepare inputs without writing any files
// const { inputs, compile_params, circuit_name } = preparePassportInputs(passportData);

// Now you can use these inputs in your application:
// - Send to backend API
// - Store in database
// - Use for ZK proof generation
// - etc.

console.log('=== Example 2: Read from file and prepare inputs ===\n');

const passportFromFile = readJsonFileSync('./germ.json');
const result = preparePassportInputs(passportFromFile);

console.log('Circuit name:', result.circuit_name);
console.log('Signature type:', result.compile_params.sig_type);
console.log('DG1 length:', result.compile_params.dg1_len);
console.log('Hash type:', result.compile_params.hash_type);
console.log('\nInputs are now in native format:');
console.log('- dg1: Array of', result.inputs.dg1.length, 'bytes (number[])');
console.log('- pk: Array of', result.inputs.pk.length, 'bigints');
console.log('- sk_identity:', typeof result.inputs.sk_identity, '=', result.inputs.sk_identity.toString(16));
console.log('- icao_root:', typeof result.inputs.icao_root, '=', result.inputs.icao_root.toString(16));
console.log('\nNo need to convert from strings to numbers!');

console.log('\n=== Example 3: Using poseidon hash ===\n');

const hash1 = poseidon([123n, 456n, 789n]);
console.log('Poseidon hash of [123n, 456n, 789n]:', hash1);

const hash2 = poseidon([BigInt("0x1234"), BigInt("0x5678")]);
console.log('Poseidon hash of [0x1234, 0x5678]:', hash2);

console.log('\n=== Example 4: ASN.1 utilities ===\n');

// Decode SOD from passport
const sodDecoded = decoded(passportFromFile.sod);
console.log('SOD decoded, type:', sodDecoded.name);
console.log('SOD has sub-elements:', Array.isArray(sodDecoded.sub));

console.log('\n=== All utilities are available! ===');
console.log('You can now use these in your TypeScript/JavaScript application');
console.log('Import them as: import { preparePassportInputs, poseidon, decoded } from "passport-zk-circuits"');
