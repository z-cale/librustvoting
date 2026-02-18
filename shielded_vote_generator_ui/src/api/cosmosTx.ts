// Client-side Cosmos SDK transaction signing and REST broadcasting.
//
// MsgSetVoteManager (and MsgCreateVotingSession) are standard Cosmos SDK
// transactions. Instead of relying on a server-side handler, we sign them
// directly in the browser using cosmjs and broadcast via the chain's REST
// API (/cosmos/tx/v1beta1/txs).

import {
  DirectSecp256k1Wallet,
  Registry,
  makeSignDoc,
  makeAuthInfoBytes,
  encodePubkey,
} from "@cosmjs/proto-signing";
import { encodeSecp256k1Pubkey } from "@cosmjs/amino";
import { fromHex, toBase64, fromBase64 } from "@cosmjs/encoding";
import { TxRaw } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import type { BroadcastResult } from "./chain";

const BECH32_PREFIX = "zvote";
const DEFAULT_GAS = "200000";

// ── Protobuf types for custom messages ──────────────────────────

// Minimal protobuf Writer that produces valid wire-format bytes.
// Only supports varint + length-delimited (string/bytes) fields,
// which is sufficient for the message types below.
class ProtoWriter {
  private parts: Uint8Array[] = [];

  static create(): ProtoWriter {
    return new ProtoWriter();
  }

  uint32(value: number): this {
    this.writeVarint(value >>> 0);
    return this;
  }

  string(value: string): this {
    const encoded = new TextEncoder().encode(value);
    this.writeVarint(encoded.length);
    this.parts.push(encoded);
    return this;
  }

  finish(): Uint8Array {
    let totalLength = 0;
    for (const p of this.parts) totalLength += p.length;
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const p of this.parts) {
      result.set(p, offset);
      offset += p.length;
    }
    return result;
  }

  private writeVarint(value: number) {
    const bytes: number[] = [];
    let v = value >>> 0;
    while (v > 0x7f) {
      bytes.push((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    bytes.push(v);
    this.parts.push(new Uint8Array(bytes));
  }
}

// Proto: message MsgSetVoteManager { string creator = 1; string new_manager = 2; }
const MsgSetVoteManagerProto = {
  encode(
    message: { creator: string; newManager: string },
    writer: ProtoWriter = ProtoWriter.create(),
  ): ProtoWriter {
    if (message.creator !== "") {
      writer.uint32(10).string(message.creator); // field 1, wire type 2
    }
    if (message.newManager !== "") {
      writer.uint32(18).string(message.newManager); // field 2, wire type 2
    }
    return writer;
  },
  decode(): { creator: string; newManager: string } {
    throw new Error("decode not implemented");
  },
  fromPartial(
    object: Partial<{ creator: string; newManager: string }>,
  ): { creator: string; newManager: string } {
    return {
      creator: object.creator ?? "",
      newManager: object.newManager ?? "",
    };
  },
};

function createRegistry(): Registry {
  const registry = new Registry();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  registry.register("/zvote.v1.MsgSetVoteManager", MsgSetVoteManagerProto as any);
  return registry;
}

// ── REST helpers ────────────────────────────────────────────────

async function fetchAccountInfo(
  apiBase: string,
  address: string,
): Promise<{ accountNumber: number; sequence: number }> {
  const resp = await fetch(`${apiBase}/cosmos/auth/v1beta1/accounts/${address}`);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to fetch account info: HTTP ${resp.status} – ${text}`);
  }
  const data = await resp.json();
  const account = data.account ?? {};
  return {
    accountNumber: parseInt(account.account_number ?? "0", 10),
    sequence: parseInt(account.sequence ?? "0", 10),
  };
}

async function fetchChainId(apiBase: string): Promise<string> {
  const resp = await fetch(`${apiBase}/cosmos/base/tendermint/v1beta1/node_info`);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to fetch node info: HTTP ${resp.status} – ${text}`);
  }
  const data = await resp.json();
  return data.default_node_info?.network ?? "";
}

async function broadcastTxRest(
  apiBase: string,
  txBytes: Uint8Array,
): Promise<BroadcastResult> {
  const resp = await fetch(`${apiBase}/cosmos/tx/v1beta1/txs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tx_bytes: toBase64(txBytes),
      mode: "BROADCAST_MODE_SYNC",
    }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Broadcast failed: HTTP ${resp.status} – ${text}`);
  }
  const data = await resp.json();
  const txResp = data.tx_response ?? {};
  return {
    tx_hash: txResp.txhash ?? "",
    code: txResp.code ?? -1,
    log: txResp.raw_log ?? "",
  };
}

// ── Signing ─────────────────────────────────────────────────────

interface SignAndBroadcastOptions {
  apiBase: string;
  privateKeyHex: string;
  messages: Array<{ typeUrl: string; value: Record<string, unknown> }>;
  memo?: string;
  gas?: string;
}

async function signAndBroadcast({
  apiBase,
  privateKeyHex,
  messages,
  memo = "",
  gas = DEFAULT_GAS,
}: SignAndBroadcastOptions): Promise<BroadcastResult> {
  const privkey = fromHex(privateKeyHex);
  const wallet = await DirectSecp256k1Wallet.fromKey(privkey, BECH32_PREFIX);
  const [account] = await wallet.getAccounts();

  const [{ accountNumber, sequence }, chainId] = await Promise.all([
    fetchAccountInfo(apiBase, account.address),
    fetchChainId(apiBase),
  ]);

  const registry = createRegistry();
  const txBodyBytes = registry.encodeTxBody({ messages, memo });

  const pubkey = encodePubkey(encodeSecp256k1Pubkey(account.pubkey));
  const gasLimit = parseInt(gas, 10);
  const authInfoBytes = makeAuthInfoBytes(
    [{ pubkey, sequence }],
    [],
    gasLimit,
    undefined,
    undefined,
    SignMode.SIGN_MODE_DIRECT,
  );

  const signDoc = makeSignDoc(txBodyBytes, authInfoBytes, chainId, accountNumber);
  const { signature, signed } = await wallet.signDirect(account.address, signDoc);

  const txRaw = TxRaw.fromPartial({
    bodyBytes: signed.bodyBytes,
    authInfoBytes: signed.authInfoBytes,
    signatures: [fromBase64(signature.signature)],
  });
  const txBytes = TxRaw.encode(txRaw).finish();

  return broadcastTxRest(apiBase, txBytes);
}

// ── Public API ──────────────────────────────────────────────────

/**
 * Derive the bech32 address from a hex-encoded secp256k1 private key.
 */
export async function deriveAddress(privateKeyHex: string): Promise<string> {
  const privkey = fromHex(privateKeyHex);
  const wallet = await DirectSecp256k1Wallet.fromKey(privkey, BECH32_PREFIX);
  const [account] = await wallet.getAccounts();
  return account.address;
}

/**
 * Sign and broadcast a MsgSetVoteManager transaction.
 *
 * The `creator` field is derived from the private key (the signer must be
 * the current vote manager or a bonded validator).
 */
export async function setVoteManager(
  apiBase: string,
  privateKeyHex: string,
  newManager: string,
): Promise<BroadcastResult> {
  const signerAddress = await deriveAddress(privateKeyHex);

  return signAndBroadcast({
    apiBase,
    privateKeyHex,
    messages: [
      {
        typeUrl: "/zvote.v1.MsgSetVoteManager",
        value: { creator: signerAddress, newManager },
      },
    ],
  });
}
