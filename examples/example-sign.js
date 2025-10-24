/* package.json
{
  "name": "test",
  "version": "0.0.1",
  "description": "test",
  "main": "example-sign.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "rialo",
  "license": "ISC",
  "dependencies": {
    "@ledgerhq/hw-transport-node-hid": "5.17.0",
    "bs58": "4.0.1",
    "tweetnacl": "1.0.3",
    "@solana/web3.js": "0.90.0",
    "assert": "2.0.0"
  }
}
*/

const Transport = require("@ledgerhq/hw-transport-node-hid").default;
const bs58 = require("bs58");
const nacl = require("tweetnacl");
const solana = require("@solana/web3.js");
const assert = require("assert");
const isValidUTF8 = require("utf-8-validate");
const crypto = require("crypto");

const INS_GET_APP_CONFIG = 0x04;
const INS_GET_PUBKEY = 0x05;
const INS_SIGN_MESSAGE = 0x06;
const INS_SIGN_OFFCHAIN_MESSAGE = 0x07;

const P1_NON_CONFIRM = 0x00;
const P1_CONFIRM = 0x01;

const P2_EXTEND = 0x01;
const P2_MORE = 0x02;

const MAX_PAYLOAD = 255;

const LEDGER_CLA = 0xe0;

const STATUS_OK = 0x9000;

// Max off-chain message length supported by Ledger
const OFFCM_MAX_LEDGER_LEN = 1212;
// Max length of version 0 off-chain message
const OFFCM_MAX_V0_LEN = 65515;

class OffchainMessage {
  /**
   * Constructs a new OffchainMessage
   * @param {version: number, messageFormat: number, message: string | Buffer} opts - Constructor parameters
   */
  constructor(opts) {
    this.version = 0;
    this.messageFormat = undefined;
    this.message = undefined;

    if (!opts) {
      return;
    }
    if (opts.version) {
      this.version = opts.version;
    }
    if (opts.messageFormat) {
      this.messageFormat = opts.messageFormat;
    }
    if (opts.message) {
      this.message = Buffer.from(opts.message);
      if (this.version === 0) {
        if (!this.messageFormat) {
          this.messageFormat = OffchainMessage.guessMessageFormat(this.message);
        }
      }
    }
  }

  static guessMessageFormat(message) {
    if (Object.prototype.toString.call(message) !== "[object Uint8Array]") {
      return undefined;
    }
    if (message.length <= OFFCM_MAX_LEDGER_LEN) {
      if (OffchainMessage.isPrintableASCII(message)) {
        return 0;
      } else if (OffchainMessage.isUTF8(message)) {
        return 1;
      }
    } else if (message.length <= OFFCM_MAX_V0_LEN) {
      if (OffchainMessage.isUTF8(message)) {
        return 2;
      }
    }
    return undefined;
  }

  static isPrintableASCII(buffer) {
    return (
      buffer &&
      buffer.every((element) => {
        return element >= 0x20 && element <= 0x7e;
      })
    );
  }

  static isUTF8(buffer) {
    return buffer && isValidUTF8(buffer);
  }

  isValid() {
    if (this.version !== 0) {
      return false;
    }
    let format = OffchainMessage.guessMessageFormat(this.message);
    return format != null && format === this.messageFormat;
  }

  isLedgerSupported(allowBlindSigning) {
    return (
      this.isValid() &&
      (this.messageFormat === 0 ||
        (this.messageFormat === 1 && allowBlindSigning))
    );
  }

  serialize() {
    if (!this.isValid()) {
      throw new Error(`Invalid OffchainMessage: ${JSON.stringify(this)}`);
    }
    let buffer = Buffer.alloc(4);
    let offset = buffer.writeUInt8(this.version);
    offset = buffer.writeUInt8(this.messageFormat, offset);
    offset = buffer.writeUInt16LE(this.message.length, offset);
    return Buffer.concat([
      Buffer.from([255]),
      Buffer.from("rialo offchain"),
      buffer,
      this.message,
    ]);
  }

  verifySignature(signature, publicKey) {
    return nacl.sign.detached.verify(
      this.serialize(),
      signature,
      publicKey.toBuffer()
    );
  }
}

/*
 * Helper for chunked send of large payloads
 */
async function solanaSend(transport, instruction, p1, payload) {
  var p2 = 0;
  var payload_offset = 0;

  if (payload.length > MAX_PAYLOAD) {
    while (payload.length - payload_offset > MAX_PAYLOAD) {
      const buf = payload.slice(payload_offset, payload_offset + MAX_PAYLOAD);
      payload_offset += MAX_PAYLOAD;
      console.log(
        "send",
        (p2 | P2_MORE).toString(16),
        buf.length.toString(16),
        buf
      );
      const reply = await transport.send(
        LEDGER_CLA,
        instruction,
        p1,
        p2 | P2_MORE,
        buf
      );
      if (reply.length != 2) {
        throw new TransportError(
          "solanaSend: Received unexpected reply payload",
          "UnexpectedReplyPayload"
        );
      }
      p2 |= P2_EXTEND;
    }
  }

  const buf = payload.slice(payload_offset);
  console.log("send", p2.toString(16), buf.length.toString(16), buf);
  const reply = await transport.send(LEDGER_CLA, instruction, p1, p2, buf);

  return reply.slice(0, reply.length - 2);
}

const BIP32_HARDENED_BIT = (1 << 31) >>> 0;
function _harden(n) {
  return (n | BIP32_HARDENED_BIT) >>> 0;
}

function solanaDerivationPath(account, change) {
  var length;
  if (typeof account === "number") {
    if (typeof change === "number") {
      length = 4;
    } else {
      length = 3;
    }
  } else {
    length = 2;
  }

  var derivation_path = Buffer.alloc(1 + length * 4);
  var offset = 0;
  offset = derivation_path.writeUInt8(length, offset);
  offset = derivation_path.writeUInt32BE(_harden(44), offset); // Using BIP44
  offset = derivation_path.writeUInt32BE(_harden(501), offset); // Rialo's BIP44 path

  if (length > 2) {
    offset = derivation_path.writeUInt32BE(_harden(account), offset);
    if (length == 4) {
      offset = derivation_path.writeUInt32BE(_harden(change), offset);
    }
  }

  return derivation_path;
}

async function solanaLedgerGetAppConfig(transport) {
  const reply = await transport.send(
    LEDGER_CLA,
    INS_GET_APP_CONFIG,
    P1_NON_CONFIRM,
    0,
    Buffer.alloc(0)
  );

  return reply.slice(0, reply.length - 2);
}

async function solanaLedgerGetPubkey(transport, derivation_path) {
  return solanaSend(transport, INS_GET_PUBKEY, P1_NON_CONFIRM, derivation_path);
}

async function solanaLedgerSignTransaction(
  transport,
  derivation_path,
  message
) {
  const msg_bytes = message.serialize();

  // XXX: Ledger app only supports a single derivation_path per call ATM
  var num_paths = Buffer.alloc(1);
  num_paths.writeUInt8(1);

  const payload = Buffer.concat([num_paths, derivation_path, msg_bytes]);

  return solanaSend(transport, INS_SIGN_MESSAGE, P1_CONFIRM, payload);
}

async function solanaLedgerSignOffchainMessage(
  transport,
  derivation_path,
  message
) {
  if (!message.isLedgerSupported(true)) {
    throw new Error("Provided message is not supported by Ledger");
  }
  const payload = Buffer.concat([
    Buffer.from([1]),
    derivation_path,
    message.serialize(),
  ]);

  return solanaSend(transport, INS_SIGN_OFFCHAIN_MESSAGE, P1_CONFIRM, payload);
}

(async () => {
  var transport = await Transport.open();

  const app_config = await solanaLedgerGetAppConfig(transport);
  console.log("App config:", app_config);

  // get "from" pubkey for transfer instruction
  const from_derivation_path = solanaDerivationPath();
  const from_pubkey_bytes = await solanaLedgerGetPubkey(
    transport,
    from_derivation_path
  );
  const from_pubkey_string = bs58.encode(from_pubkey_bytes);
  console.log("From pubkey:", from_pubkey_string);

  // get "to" pubkey for transfer instruction
  const to_derivation_path = solanaDerivationPath(1);
  const to_pubkey_bytes = await solanaLedgerGetPubkey(
    transport,
    to_derivation_path
  );
  const to_pubkey_string = bs58.encode(to_pubkey_bytes);
  console.log("To pubkey:", to_pubkey_string);

  // create RLO transfer instruction
  const from_pubkey = new solana.PublicKey(from_pubkey_string);
  const to_pubkey = new solana.PublicKey(to_pubkey_string);
  const ix = solana.SystemProgram.transfer({
    fromPubkey: from_pubkey,
    toPubkey: to_pubkey,
    lamports: 42,
  });

  // XXX: Fake blockhash so this example doesn't need a
  // network connection. It should be queried from the
  // cluster in normal use.
  const recentBlockhash = bs58.encode(
    Buffer.from([
      3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
      3, 3, 3, 3, 3, 3, 3,
    ])
  );

  // create and sign transfer transaction
  var tx = new solana.Transaction({
    recentBlockhash: recentBlockhash,
    feePayer: from_pubkey,
  }).add(ix);

  let sig_bytes = await solanaLedgerSignTransaction(
    transport,
    from_derivation_path,
    tx.compileMessage()
  );

  let sig_string = bs58.encode(sig_bytes);
  console.log("Sig len:", sig_bytes.length, "sig:", sig_string);

  // verify transfer signature
  tx.addSignature(from_pubkey, sig_bytes);
  console.log("Sig verifies:", tx.verifySignatures());

  // create and sign versioned transfer transaction
  const messageV0 = solana.MessageV0.compile({
    addressLookupTableAccounts: [],
    instructions: [ix],
    payerKey: from_pubkey,
    recentBlockhash,
  });

  sig_bytes = await solanaLedgerSignTransaction(
    transport,
    from_derivation_path,
    messageV0
  );
  sig_string = bs58.encode(sig_bytes);
  console.log("Sig len:", sig_bytes.length, "sig:", sig_string);

  let verifies = nacl.sign.detached.verify(
    messageV0.serialize(),
    sig_bytes,
    from_pubkey.toBuffer()
  );
  console.log("Sig verifies:", verifies);

  // create and sign off-chain message in ascii
  // TIP: enable expert mode in Ledger to see message details
  let message = new OffchainMessage({
    message: "Long Off-Chain Test Message.",
  });
  console.log("Off-chain message:", message);

  sig_bytes = await solanaLedgerSignOffchainMessage(
    transport,
    from_derivation_path,
    message
  );
  sig_string = bs58.encode(sig_bytes);
  console.log("Sig len:", sig_bytes.length, "sig:", sig_string);

  // verify off-chain message signature
  console.log("Sig verifies:", message.verifySignature(sig_bytes, from_pubkey));

  // create and sign off-chain message in UTF8
  // NOTE: enable blind signing in Ledger for this to work
  message = new OffchainMessage({
    message: Buffer.from("Тестовое сообщение в формате UTF-8", "utf-8"),
  });
  console.log("Off-chain message:", message);
  const hash = crypto.createHash("sha256");
  hash.update(message.serialize());
  console.log("Expected hash:", bs58.encode(hash.digest()));

  sig_bytes = await solanaLedgerSignOffchainMessage(
    transport,
    from_derivation_path,
    message
  );
  sig_string = bs58.encode(sig_bytes);
  console.log("Sig len:", sig_bytes.length, "sig:", sig_string);

  // verify off-chain message signature
  console.log("Sig verifies:", message.verifySignature(sig_bytes, from_pubkey));
})().catch((e) => console.log(e));
