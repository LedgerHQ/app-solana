#!/usr/bin/env python3
"""Seed the corpus from the curated raw Solana transactions.

The generic seeds fill the tail with arbitrary bytes, which reaches src/apdu.c
but never satisfies parse_message_header(), so nothing downstream runs on a cold
start. This wraps each recorded transaction under seeds/raw-transactions/ in a
SignMessage APDU so the parsers have a starting point to mutate from.

The transactions are recorded wire bytes, not constructed here: no field is
computed, so libFuzzer remains free to make any of them inconsistent.

Seed layout, all offsets relative to the start of the harness input (Absolution
consumes the prefix before the harness sees anything):

    [0] lane selector   [1] index into fuzz_commands[]   [2] P1   [3] P2
    [4:] APDU payload, passed to apdu_handle_message()
"""

import os
import struct
import sys

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "..", "..", "ledger-secure-sdk",
                                "fuzzing", "scripts"))

from fuzz_seed_utils import (  # noqa: E402
    resolve_prefix_size,
    resolve_seed_prefix,
    ctrl_bytes,
)

RAW_DIR = os.path.join(SCRIPT_DIR, "..", "seeds", "raw-transactions")

# Index into fuzz_commands[] in fuzzing/harness/fuzz_dispatcher.c.
IDX_SIGN_MESSAGE = 5

# Solana canonical derivation path: m/44'/501'/0'/0'/0'.
BIP32_PATH = [0x8000002C, 0x800001F5, 0x80000000, 0x80000000, 0x80000000]


def sign_message_payload(message):
    """[u8 num_derivation_paths=1] [u8 components] [BE words] [message]"""
    out = bytearray([1, len(BIP32_PATH)])
    for word in BIP32_PATH:
        out += struct.pack(">I", word)
    return bytes(out) + message


def generate_seeds(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    base_prefix = resolve_seed_prefix(resolve_prefix_size())

    raw_files = sorted(f for f in os.listdir(RAW_DIR) if f.endswith(".raw"))
    written = 0

    for i, name in enumerate(raw_files):
        with open(os.path.join(RAW_DIR, name), "rb") as fh:
            payload = sign_message_payload(fh.read())

        # Raw lane for every transaction; structured lane for a few, so the
        # lane the TLV grammar mutator drives is seeded too.
        lanes = [False, True] if i % 10 == 0 else [False]
        for structured in lanes:
            ctrl = ctrl_bytes(structured, cmd_idx=IDX_SIGN_MESSAGE)
            tag = "struct" if structured else "raw"
            out = os.path.join(output_dir, f"custom_{tag}_{name[:-4]}")
            with open(out, "wb") as fh:
                fh.write(base_prefix + ctrl + payload)
            written += 1

    print(f"[custom] Wrote {written} seeds from {len(raw_files)} transactions in {output_dir}")


if __name__ == "__main__":
    generate_seeds(sys.argv[1] if len(sys.argv) > 1 else "base-corpus")
