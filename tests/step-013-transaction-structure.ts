/**
 * AETHER LEARNING SYSTEM - STEP 013: BITCOIN TRANSACTION STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════
 * Build and parse Bitcoin transaction objects
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";

export interface TxInput {
  prevTxId: string; // Previous transaction ID
  prevOutputIndex: number; // Output index
  scriptSig: Uint8Array; // Unlocking script
  sequence: number;
}

export interface TxOutput {
  value: BigInt; // Satoshis (1 BTC = 100,000,000 satoshis)
  scriptPubKey: Uint8Array; // Locking script
}

export interface Transaction {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
  txid?: string; // Double SHA256 hash
}

/**
 * Create a new transaction
 */
export function createTransaction(): Transaction {
  return {
    version: 1,
    inputs: [],
    outputs: [],
    locktime: 0,
  };
}

/**
 * Add input to transaction
 */
export function addInput(tx: Transaction, prevTxId: string, prevOutputIndex: number, scriptSig: Uint8Array = new Uint8Array(0)): void {
  tx.inputs.push({
    prevTxId,
    prevOutputIndex,
    scriptSig,
    sequence: 0xffffffff,
  });
}

/**
 * Add output to transaction
 */
export function addOutput(tx: Transaction, value: BigInt, scriptPubKey: Uint8Array): void {
  tx.outputs.push({ value, scriptPubKey });
}

/**
 * Serialize transaction to bytes
 */
export function serializeTransaction(tx: Transaction): Uint8Array {
  let size = 4; // version (4 bytes)
  size += 1; // input count (varint, simplified as 1 byte)
  size += tx.inputs.length * (32 + 4 + 1 + 40); // simplified sizes
  size += 1; // output count
  size += tx.outputs.length * (8 + 1 + 32); // simplified sizes
  size += 4; // locktime

  const buffer = new Uint8Array(size * 2); // Allocate more space
  let pos = 0;

  // Write version (little-endian)
  writeUInt32LE(buffer, pos, tx.version);
  pos += 4;

  // Write input count
  buffer[pos++] = tx.inputs.length;

  // Write inputs
  for (const input of tx.inputs) {
    // Write previous transaction ID (reversed)
    const prevTxBytes = hexToBytes(input.prevTxId);
    buffer.set(prevTxBytes.reverse(), pos);
    pos += 32;

    // Write previous output index (little-endian)
    writeUInt32LE(buffer, pos, input.prevOutputIndex);
    pos += 4;

    // Write script length and script
    buffer[pos++] = input.scriptSig.length;
    buffer.set(input.scriptSig, pos);
    pos += input.scriptSig.length;

    // Write sequence
    writeUInt32LE(buffer, pos, input.sequence);
    pos += 4;
  }

  // Write output count
  buffer[pos++] = tx.outputs.length;

  // Write outputs
  for (const output of tx.outputs) {
    // Write value (little-endian, 8 bytes)
    writeUInt64LE(buffer, pos, output.value);
    pos += 8;

    // Write script length and script
    buffer[pos++] = output.scriptPubKey.length;
    buffer.set(output.scriptPubKey, pos);
    pos += output.scriptPubKey.length;
  }

  // Write locktime
  writeUInt32LE(buffer, pos, tx.locktime);
  pos += 4;

  return buffer.slice(0, pos);
}

/**
 * Calculate transaction ID (TXID)
 */
export function calculateTxId(tx: Transaction): string {
  const serialized = serializeTransaction(tx);
  const hash1 = sha256(serialized);
  const hash2 = sha256(hash1);
  return bytesToHex(hash2.reverse());
}

/**
 * Calculate transaction size in bytes
 */
export function calculateTxSize(tx: Transaction): number {
  return serializeTransaction(tx).length;
}

/**
 * Helper: Write UInt32 in little-endian
 */
function writeUInt32LE(buffer: Uint8Array, offset: number, value: number): void {
  buffer[offset] = value & 0xff;
  buffer[offset + 1] = (value >> 8) & 0xff;
  buffer[offset + 2] = (value >> 16) & 0xff;
  buffer[offset + 3] = (value >> 24) & 0xff;
}

/**
 * Helper: Write UInt64 in little-endian
 */
function writeUInt64LE(buffer: Uint8Array, offset: number, value: BigInt): void {
  for (let i = 0; i < 8; i++) {
    buffer[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
  }
}

/**
 * Helper: Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Helper: Convert bytes to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += ("0" + byte.toString(16)).slice(-2);
  }
  return hex;
}

export { sha256 };
