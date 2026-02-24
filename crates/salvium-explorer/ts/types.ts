/**
 * TypeScript type definitions for salvium-crypto and salvium-explorer WASM APIs.
 *
 * These interfaces describe the JSON structures returned by the WASM functions.
 * Use alongside the generated wasm-bindgen .d.ts for full type safety.
 */

// ─── Address Types ──────────────────────────────────────────────────────────

export type NetworkName = "mainnet" | "testnet" | "stagenet";
export type AddressFormatName = "legacy" | "carrot";
export type AddressTypeName = "standard" | "integrated" | "subaddress";

/** Returned by `wasm_parse_address()` */
export interface ParsedAddress {
  network: NetworkName;
  format: AddressFormatName;
  address_type: AddressTypeName;
  spend_public_key: string; // hex
  view_public_key: string;  // hex
  payment_id?: string;      // hex, only for integrated addresses
}

// ─── Transaction Extra ──────────────────────────────────────────────────────

/** Returned by `parse_extra()` */
export interface ParsedExtra {
  pubkey?: string;           // hex, 32-byte tx public key
  nonces?: ExtraNonce[];
  additionalPubkeys?: string[]; // hex array
  mysteriousMinergateTag?: string;
  padding?: number;
  unknownTags?: UnknownTag[];
}

export interface ExtraNonce {
  type: "payment_id" | "encrypted_payment_id" | "unknown";
  data: string; // hex
}

export interface UnknownTag {
  tag: number;
  data: string; // hex
}

// ─── Transaction Input/Output ───────────────────────────────────────────────

export interface TxInputGen {
  type: 0xff;
  height: number;
}

export interface TxInputKey {
  type: 0x02;
  amount: string;       // decimal string
  assetType: string;
  keyOffsets: number[];
  keyImage: string;     // hex
}

export type TxInput = TxInputGen | TxInputKey;

export interface TxOutputKey {
  type: 0x02;
  amount: string;       // decimal string
  key: string;          // hex
  assetType: string;
  unlockTime: number;
}

export interface TxOutputTaggedKey {
  type: 0x03;
  amount: string;
  key: string;
  assetType: string;
  unlockTime: number;
  viewTag: number;
}

export interface TxOutputCarrotV1 {
  type: 0x04;
  amount: string;
  key: string;
  assetType: string;
  viewTag: string;                // hex, 3 bytes
  encryptedJanusAnchor: string;   // hex, 16 bytes
}

export type TxOutput = TxOutputKey | TxOutputTaggedKey | TxOutputCarrotV1;

// ─── RCT Signature ──────────────────────────────────────────────────────────

export interface RctSignature {
  type: number;
  txnFee?: string;        // decimal string
  ecdhInfo?: EcdhInfo[];
  outPk?: string[];       // hex, commitment points
  pseudoOuts?: string[];  // hex
}

export interface EcdhInfo {
  amount: string; // hex-encoded encrypted amount
}

// ─── Parsed Transaction (from parse_transaction_bytes) ──────────────────────

/** Returned by `parse_transaction_bytes()` */
export interface ParsedTransaction {
  prefix: {
    version: number;
    unlockTime: number;
    vin: TxInput[];
    vout: TxOutput[];
    extra: ParsedExtra;
    txType: number;
    amountBurnt?: string;
    returnAddress?: string;
    returnAddressList?: string[];
    returnAddressChangeMask?: string;
    returnPubkey?: string;
    sourceAssetType?: string;
    destinationAssetType?: string;
    amountSlippageLimit?: string;
    protocolTxData?: ProtocolTxData;
  };
  rct: RctSignature;
  _bytesRead: number;
  _prefixEndOffset: number;
}

export interface ProtocolTxData {
  stakeTxId?: string;
  returnTxId?: string;
  convertTxId?: string;
  convertRequestAmount?: string;
  convertRequestSourceAsset?: string;
  convertRequestDestAsset?: string;
}

// ─── Parsed Block (from parse_block_bytes) ──────────────────────────────────

/** Returned by `parse_block_bytes()` */
export interface ParsedBlock {
  majorVersion: number;
  minorVersion: number;
  timestamp: number;
  prevId: string;          // hex, 32-byte block hash
  nonce: number;
  minerTx: ParsedTransaction;
  txHashes: string[];      // hex array
}

// ─── Analyzed Transaction (from parse_and_analyze_tx) ───────────────────────

/** Returned by `parse_and_analyze_tx()` — extends ParsedTransaction */
export interface AnalyzedTransaction extends ParsedTransaction {
  tx_type_name: string;
  rct_type_name: string;
  input_count: number;
  output_count: number;
  is_coinbase: boolean;
  is_carrot: boolean;
  key_images: string[];    // hex array
  output_keys: string[];   // hex array
  fee: string;             // decimal string
}

// ─── Analyzed Block (from parse_and_analyze_block) ──────────────────────────

/** Returned by `parse_and_analyze_block()` — extends ParsedBlock */
export interface AnalyzedBlock extends ParsedBlock {
  tx_count: number;
}

// ─── Decoded Output (from decode_outputs_for_view_key) ──────────────────────

/** Element of the array returned by `decode_outputs_for_view_key()` */
export interface DecodedOutput {
  output_index: number;
  amount: string;           // decimal string
  output_key: string;       // hex
  subaddress_major: number;
  subaddress_minor: number;
}
