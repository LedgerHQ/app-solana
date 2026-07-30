import hashlib
import struct

import pytest

from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.instruction import Instruction, AccountMeta

from application_client.solana import (SolanaClient, INS, CLA, P2_NONE, P1_NON_CONFIRM, ErrorType,
                                      TokenAccountStateTag, AltResolutionTag, EnumVariantTag,
                                      InstructionInfoTag, ValueTag)
from application_client.solana_signing_partners import GENERIC_CLEAR_SIGNING_PARTNER
from application_client.solana_cmd_builder import verify_signature
from application_client.tlv import format_tlv
from application_client import solana_utils as SOL


# DISPLAY_FIELD / PARAM / VALUE source tag values (spec/device/tlv_structs.md)
DISPLAY_FIELD_TAG_VERSION = 0x00
DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE = 0x01
DISPLAY_FIELD_TAG_NAME = 0x02
DISPLAY_FIELD_TAG_PARAM_TYPE = 0x03
DISPLAY_FIELD_TAG_PARAM = 0x04
PARAM_TYPE_RAW = 0x00
PARAM_TYPE_AMOUNT = 0x01
PARAM_TYPE_TOKEN_AMOUNT = 0x02
PARAM_TYPE_DATETIME = 0x03
PARAM_TYPE_DURATION = 0x04
PARAM_TYPE_UNIT = 0x05
PARAM_TYPE_ENUM = 0x06
PARAM_TYPE_TRUSTED_NAME = 0x07
PARAM_TYPE_ACCOUNT = 0x08
PARAM_TYPE_STRING = 0x09
PARAM_TAG_VERSION = 0x00
PARAM_TAG_VALUE = 0x01
PARAM_TAG_DECIMALS = 0x02  # PARAM_AMOUNT tag for decimals
PARAM_TAG_KIND = 0x02      # PARAM_RAW/CONSTANT tag for IDL kind
PARAM_TAG_IS_NATIVE = 0x04  # PARAM_TOKEN_AMOUNT tag for is_native flag
PARAM_AMOUNT_TAG_MAX_LABEL = 0x03  # PARAM_AMOUNT MAX_LABEL sentinel string
PARAM_TOKEN_TAG_MAX_LABEL = 0x05   # PARAM_TOKEN_AMOUNT MAX_LABEL sentinel string
PARAM_ENUM_TAG_SKIP_INNER = 0x02   # PARAM_ENUM 1=render variant name only
PARAM_DATETIME_TAG_TICKS = 0x02       # PARAM_DATETIME ticks-per-second (BE uint)
PARAM_UNIT_TAG_SYMBOL = 0x02          # PARAM_UNIT symbol string
PARAM_UNIT_TAG_DECIMALS = 0x03        # PARAM_UNIT decimal scaling
PARAM_UNIT_TAG_PREFIX = 0x04          # PARAM_UNIT 1=symbol before value
PARAM_STRING_TAG_ENCODING = 0x02      # PARAM_STRING encoding selector
PARAM_STRING_TAG_SLICE_KIND = 0x03    # PARAM_STRING slice kind (bounded/sized)
PARAM_STRING_TAG_SLICE_START = 0x04   # PARAM_STRING slice start (BE u16)
PARAM_STRING_TAG_SLICE_END = 0x05     # PARAM_STRING bounded slice end (BE u16)
PARAM_STRING_TAG_SLICE_SIZE = 0x06    # PARAM_STRING sized slice size (BE u16)
PARAM_STRING_TAG_SLICE_REVERSED = 0x07  # PARAM_STRING sized slice from tail
PARAM_STRING_TAG_SLICE_APPLIES_TO = 0x08  # PARAM_STRING 0=formatted, 1=source
STRING_ENCODING_ASCII = 0x00
STRING_ENCODING_UTF8 = 0x01
STRING_ENCODING_BASE58 = 0x02
STRING_ENCODING_BASE64 = 0x03
STRING_ENCODING_HEX = 0x04
SLICE_KIND_BOUNDED = 0x00
SLICE_KIND_SIZED = 0x01
SLICE_APPLIES_TO_FORMATTED = 0x00
SLICE_APPLIES_TO_SOURCE = 0x01
PARAM_TOKEN_TAG_TOKEN = 0x02     # PARAM_TOKEN_AMOUNT tag for the TOKEN reference (VALUE)
PARAM_TOKEN_TAG_DECIMALS = 0x03  # PARAM_TOKEN_AMOUNT tag for the DECIMALS override (VALUE)
PARAM_TRUSTED_NAME_TAG_TYPES = 0x02   # PARAM_TRUSTED_NAME allowed TrustedNameType list
TRUSTED_NAME_TYPE_SMART_CONTRACT = 0x02
TRUSTED_NAME_TYPE_TOKEN = 0x04
VALUE_SOURCE_ARGUMENT_PATH = 0x00
VALUE_SOURCE_ACCOUNT_PATH = 0x01
VALUE_SOURCE_CONSTANT = 0x02
IDL_KIND_U32 = 0x03
IDL_KIND_U64 = 0x04
IDL_KIND_U128 = 0x05
IDL_KIND_I64 = 0x09
IDL_KIND_I128 = 0x0A
IDL_KIND_F32 = 0x0B
IDL_KIND_F64 = 0x0C
IDL_KIND_SHORT_U16 = 0x0D
IDL_KIND_BOOL_U16 = 0x0F
IDL_KIND_PUBKEY_32 = 0x11
IDL_KIND_BYTES_FIXED = 0x12
IDL_KIND_STRING_PREFIXED = 0x14
SUBSTRUCTURE_TYPE_DISPLAY_FIELD = 0x00
SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT = 0x01
SUBSTRUCTURE_TYPE_HIDE_RULE = 0x02
SUBSTRUCTURE_TYPE_ACCOUNT_RESET = 0x03

# VALUE_FLOW_PORT / HIDE_RULE / ACCOUNT_RESET tag values (spec/device/tlv_structs.md)
VFP_TAG_VERSION = 0x00
VFP_TAG_SUBSTRUCT_TYPE = 0x01
VFP_TAG_DIRECTION = 0x02
VFP_TAG_ACCOUNT_INDEX = 0x03
VFP_TAG_VALUE_KIND = 0x04
VFP_TAG_AMOUNT_VALUE = 0x05
VFP_TAG_TOKEN_VALUE = 0x06
VFP_TAG_ACTIVE_WHEN = 0x07
VFP_TAG_STRATEGY = 0x08
PORT_DIRECTION_INPUT = 0x00
PORT_DIRECTION_OUTPUT = 0x01
PORT_VALUE_KIND_NATIVE = 0x00
PORT_VALUE_KIND_SPL_TOKEN = 0x01
AMOUNT_VALUE_TAG_KIND = 0x01
AMOUNT_VALUE_TAG_VALUE = 0x02
AMOUNT_KIND_NUMERIC = 0x00
AMOUNT_KIND_BALANCE = 0x01
TOKEN_VALUE_TAG_KIND = 0x01
TOKEN_VALUE_TAG_VALUE = 0x02
TOKEN_VALUE_TAG_ACCOUNT = 0x03
TOKEN_VALUE_TAG_FALLBACK = 0x04
TOKEN_KIND_DIRECT = 0x00
TOKEN_KIND_RESOLVE = 0x01
TOKEN_KIND_NULL = 0x02
TOKEN_KIND_NATIVE = 0x03
OPTIONAL_ACCOUNT_STRATEGY_PROGRAM_ID = 0x00
OPTIONAL_ACCOUNT_STRATEGY_OMITTED = 0x01
HIDE_RULE_TAG_VERSION = 0x00
HIDE_RULE_TAG_SUBSTRUCT_TYPE = 0x01
HIDE_RULE_TAG_RULE_SET_INDEX = 0x02
HIDE_RULE_TAG_TARGET = 0x03
HIDE_RULE_TAG_CONDITION = 0x04
HIDE_CONDITION_IS_SIGNER = 0x01
HIDE_CONDITION_ACCOUNT_EFFECTS_DISPLAYED_ELSEWHERE = 0x04
ACCOUNT_RESET_TAG_VERSION = 0x00
ACCOUNT_RESET_TAG_SUBSTRUCT_TYPE = 0x01
ACCOUNT_RESET_TAG_ACCOUNT_INDEX = 0x02
ACCOUNT_RESET_TAG_REQUIRE_ZERO = 0x03
ACCOUNT_RESET_TAG_RESET_VALUE = 0x04
ACCOUNT_RESET_TAG_RESET_SCOPE = 0x05
RESET_SCOPE_TAG_PROGRAM_ID = 0x01
RESET_SCOPE_TAG_DISCRIMINATOR = 0x02


def _begin_session(sol: SolanaClient, message: bytes) -> None:
    """Open a clear-signing context by sending START GENERIC CLEAR SIGNING SESSION (0x0A)."""
    sol.start_generic_clear_signing_session(SOL.SOL_PACKED_DERIVATION_PATH, message)


def _wipe_session(sol: SolanaClient) -> None:
    """End a partial clear-signing flow. A garbage APDU is rejected with 0x6d00 and, on that error
    reply, the app wipes the parked session and delayed-sign fingerprint so nothing lingers."""
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.send_false_apdu()
    assert exc_info.value.status == ErrorType.UNIMPLEMENTED_INSTRUCTION


def _craft_single_instruction_message(sol: SolanaClient, program_id: bytes, data: bytes) -> bytes:
    sender = Pubkey.from_bytes(sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH))
    instruction = Instruction(
        program_id=Pubkey.from_bytes(program_id),
        accounts=[AccountMeta(pubkey=sender, is_signer=True, is_writable=True)],
        data=data,
    )
    return sol.craft_tx([instruction], sender)


def _craft_instruction_with_accounts(sol: SolanaClient, program_id: bytes, data: bytes,
                                     extra_accounts: list) -> bytes:
    """Build a message with one instruction carrying extra non-signer accounts."""
    sender = Pubkey.from_bytes(sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH))
    accounts = [AccountMeta(pubkey=sender, is_signer=True, is_writable=True)]
    for pubkey_bytes in extra_accounts:
        accounts.append(AccountMeta(pubkey=Pubkey.from_bytes(pubkey_bytes),
                                    is_signer=False, is_writable=True))
    instruction = Instruction(
        program_id=Pubkey.from_bytes(program_id),
        accounts=accounts,
        data=data,
    )
    return sol.craft_tx([instruction], sender)


def _craft_multi_instruction_message(sol: SolanaClient, program_id: bytes, data: bytes,
                                     count: int) -> bytes:
    """Build a message repeating one identical instruction `count` times. All
    instances share a single (program_id, discriminator) template."""
    sender = Pubkey.from_bytes(sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH))
    instruction = Instruction(
        program_id=Pubkey.from_bytes(program_id),
        accounts=[AccountMeta(pubkey=sender, is_signer=True, is_writable=True)],
        data=data,
    )
    return sol.craft_tx([instruction] * count, sender)


def _build_display_field(argument_path: bytes) -> bytes:
    """A minimal DISPLAY_FIELD (PARAM_RAW) pointing at one ARGUMENT_PATH leaf."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param_raw = (format_tlv(PARAM_TAG_VERSION, 1)
                 + format_tlv(PARAM_TAG_VALUE, value_tlv))
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, "Amount")
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_RAW)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_raw))


def _build_display_field_named(argument_path: bytes, name: str) -> bytes:
    """A DISPLAY_FIELD (PARAM_RAW) pointing at one ARGUMENT_PATH leaf with a custom name."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param_raw = (format_tlv(PARAM_TAG_VERSION, 1)
                 + format_tlv(PARAM_TAG_VALUE, value_tlv))
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_RAW)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_raw))


def _build_account_display_field(account_index: int, name: str) -> bytes:
    """A DISPLAY_FIELD (PARAM_RAW) pointing at one ACCOUNT_PATH."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ACCOUNT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, bytes([account_index])))
    param_raw = (format_tlv(PARAM_TAG_VERSION, 1)
                 + format_tlv(PARAM_TAG_VALUE, value_tlv))
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_RAW)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_raw))


def _build_constant_display_field(data: bytes, kind: int, name: str) -> bytes:
    """A DISPLAY_FIELD with a CONSTANT source — value embedded in the descriptor.
    The IDL kind is sent via PARAM tag 0x02 for format_leaf rendering."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_CONSTANT)
                 + format_tlv(ValueTag.PAYLOAD, data))
    param_raw = (format_tlv(PARAM_TAG_VERSION, 1)
                 + format_tlv(PARAM_TAG_VALUE, value_tlv)
                 + format_tlv(PARAM_TAG_KIND, kind))
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_RAW)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_raw))


def _build_amount_display_field(argument_path: bytes, decimals: int, name: str, *,
                                max_label: str = None) -> bytes:
    """A DISPLAY_FIELD with PARAM_AMOUNT: numeric value with fixed decimal scaling.
    An optional MAX_LABEL is rendered when the raw leaf is at its type maximum."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param_amount = (format_tlv(PARAM_TAG_VERSION, 1)
                    + format_tlv(PARAM_TAG_VALUE, value_tlv)
                    + format_tlv(PARAM_TAG_DECIMALS, decimals))
    if max_label is not None:
        param_amount += format_tlv(PARAM_AMOUNT_TAG_MAX_LABEL, max_label)
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_AMOUNT)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_amount))


def _build_token_amount_display_field(argument_path: bytes, is_native: bool, name: str, *,
                                      max_label: str = None) -> bytes:
    """A DISPLAY_FIELD with PARAM_TOKEN_AMOUNT: native SOL or unknown token.
    An optional MAX_LABEL is rendered when the raw leaf is at its type maximum."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param_token = (format_tlv(PARAM_TAG_VERSION, 1)
                   + format_tlv(PARAM_TAG_VALUE, value_tlv))
    if is_native:
        param_token += format_tlv(PARAM_TAG_IS_NATIVE, 1)
    if max_label is not None:
        param_token += format_tlv(PARAM_TOKEN_TAG_MAX_LABEL, max_label)
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_TOKEN_AMOUNT)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_token))


def _build_token_amount_field_with_token(argument_path: bytes, name: str, *,
                                         token_source: int, token_payload: bytes,
                                         decimals: int = None) -> bytes:
    """A DISPLAY_FIELD with PARAM_TOKEN_AMOUNT carrying a TOKEN reference (and an
    optional DECIMALS override). The amount is an ARGUMENT_PATH; the TOKEN is a
    VALUE resolving to the token account or mint that identifies the token."""
    amount_value = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                    + format_tlv(ValueTag.PAYLOAD, argument_path))
    token_value = (format_tlv(ValueTag.SOURCE, token_source)
                   + format_tlv(ValueTag.PAYLOAD, token_payload))
    param_token = (format_tlv(PARAM_TAG_VERSION, 1)
                   + format_tlv(PARAM_TAG_VALUE, amount_value)
                   + format_tlv(PARAM_TOKEN_TAG_TOKEN, token_value))
    if decimals is not None:
        decimals_value = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_CONSTANT)
                          + format_tlv(ValueTag.PAYLOAD, bytes([decimals])))
        param_token += format_tlv(PARAM_TOKEN_TAG_DECIMALS, decimals_value)
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_TOKEN_AMOUNT)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_token))


def _build_enum_display_field(argument_path: bytes, name: str, *,
                              skip_inner: bytes = None) -> bytes:
    """A DISPLAY_FIELD (PARAM_ENUM) pointing at one ARGUMENT_PATH enum leaf.
    The walker resolves the leaf to the selected variant's display name. An
    optional SKIP_INNER byte marks the inner payload as display-suppressed."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param_enum = (format_tlv(PARAM_TAG_VERSION, 1)
                  + format_tlv(PARAM_TAG_VALUE, value_tlv))
    if skip_inner is not None:
        param_enum += format_tlv(PARAM_ENUM_TAG_SKIP_INNER, skip_inner)
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_ENUM)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_enum))


def _build_datetime_display_field(argument_path: bytes, name: str, *,
                                  ticks_per_second: int = None) -> bytes:
    """A DISPLAY_FIELD with PARAM_DATETIME: a numeric leaf rendered as a date/time.
    An optional TICKS_PER_SECOND (BE uint) scales the raw ticks to seconds."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param = (format_tlv(PARAM_TAG_VERSION, 1)
             + format_tlv(PARAM_TAG_VALUE, value_tlv))
    if ticks_per_second is not None:
        param += format_tlv(PARAM_DATETIME_TAG_TICKS, ticks_per_second)
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_DATETIME)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param))


def _build_duration_display_field(argument_path: bytes, name: str) -> bytes:
    """A DISPLAY_FIELD with PARAM_DURATION: a numeric leaf of seconds rendered H:MM:SS."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param = (format_tlv(PARAM_TAG_VERSION, 1)
             + format_tlv(PARAM_TAG_VALUE, value_tlv))
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_DURATION)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param))


def _build_unit_display_field(argument_path: bytes, name: str, *,
                              symbol: str, decimals: int = None, prefix: bool = False) -> bytes:
    """A DISPLAY_FIELD with PARAM_UNIT: a scaled numeric value with a symbol affix."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param = (format_tlv(PARAM_TAG_VERSION, 1)
             + format_tlv(PARAM_TAG_VALUE, value_tlv)
             + format_tlv(PARAM_UNIT_TAG_SYMBOL, symbol))
    if decimals is not None:
        param += format_tlv(PARAM_UNIT_TAG_DECIMALS, decimals)
    if prefix:
        param += format_tlv(PARAM_UNIT_TAG_PREFIX, 1)
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_UNIT)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param))


def _build_account_argument_display_field(argument_path: bytes, name: str) -> bytes:
    """A DISPLAY_FIELD with PARAM_ACCOUNT: a 32-byte argument leaf rendered as a
    base58 short-form address."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param = (format_tlv(PARAM_TAG_VERSION, 1)
             + format_tlv(PARAM_TAG_VALUE, value_tlv))
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_ACCOUNT)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param))


def _build_string_display_field(argument_path: bytes, name: str, *,
                                encoding: int = None,
                                slice_kind: int = None,
                                slice_start: int = None,
                                slice_end: int = None,
                                slice_size: int = None,
                                slice_reversed: bool = False,
                                slice_applies_to: int = None) -> bytes:
    """A DISPLAY_FIELD with PARAM_STRING: a byte leaf rendered through an encoding,
    optionally sliced (before or after encoding)."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param = (format_tlv(PARAM_TAG_VERSION, 1)
             + format_tlv(PARAM_TAG_VALUE, value_tlv))
    if encoding is not None:
        param += format_tlv(PARAM_STRING_TAG_ENCODING, encoding)
    if slice_kind is not None:
        param += format_tlv(PARAM_STRING_TAG_SLICE_KIND, slice_kind)
        if slice_start is not None:
            param += format_tlv(PARAM_STRING_TAG_SLICE_START, slice_start)
        if slice_end is not None:
            param += format_tlv(PARAM_STRING_TAG_SLICE_END, slice_end)
        if slice_size is not None:
            param += format_tlv(PARAM_STRING_TAG_SLICE_SIZE, slice_size)
        if slice_reversed:
            param += format_tlv(PARAM_STRING_TAG_SLICE_REVERSED, 1)
    if slice_applies_to is not None:
        param += format_tlv(PARAM_STRING_TAG_SLICE_APPLIES_TO, slice_applies_to)
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_STRING)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param))


def _build_trusted_name_display_field(argument_path: bytes, name: str, *,
                                      allowed_types: list = None) -> bytes:
    """A DISPLAY_FIELD with PARAM_TRUSTED_NAME: a 32-byte address argument leaf
    rendered as the cached trusted name, constrained to an optional type allow-list.
    The VALUE must be an ARGUMENT_PATH source (enforced on device)."""
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, argument_path))
    param = (format_tlv(PARAM_TAG_VERSION, 1)
             + format_tlv(PARAM_TAG_VALUE, value_tlv))
    if allowed_types is not None:
        param += format_tlv(PARAM_TRUSTED_NAME_TAG_TYPES, bytes(allowed_types))
    return (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
            + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_DISPLAY_FIELD)
            + format_tlv(DISPLAY_FIELD_TAG_NAME, name)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_TRUSTED_NAME)
            + format_tlv(DISPLAY_FIELD_TAG_PARAM, param))


# Sending a substructure without an open clear-signing session must fail closed.
def test_substructure_without_session_rejected(backend):
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD,
                                             _build_display_field(b'\x01\x00'))
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE



# ── TOKEN_ACCOUNT_STATE ──────────────────────────────────────────────────────

def test_token_account_state_without_session_rejected(backend):
    """Providing a token account state outside an open streaming session must fail closed."""
    sol = SolanaClient(backend)
    challenge = sol.get_challenge()
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_token_account_state(
            challenge=challenge,
            account_address=b'\x11' * 32,
            mint=b'\x22' * 32,
            owner=b'\x33' * 32,
            pre_balance=1_000_000,
        )
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


def test_token_account_state_valid(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    challenge = sol.get_challenge()
    sol.provide_token_account_state(
        challenge=challenge,
        account_address=b'\x11' * 32,
        mint=b'\x22' * 32,
        owner=b'\x33' * 32,
        pre_balance=1_000_000,
    )
    _wipe_session(sol)


def test_token_account_state_bad_challenge(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.get_challenge()
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_token_account_state(
            challenge=b'\x00\x00\x00\x00',  # wrong challenge
            account_address=b'\x11' * 32,
            mint=b'\x22' * 32,
            owner=b'\x33' * 32,
            pre_balance=0,
        )
    assert exc_info.value.status == ErrorType.INVALID_TOKEN_ACCOUNT_STATE


def test_token_account_state_wrong_struct_type(backend):
    """Sending wrong struct type should fail."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    challenge = sol.get_challenge()
    # Build manually with wrong struct type (0x99 instead of 0x15)
    payload = format_tlv(TokenAccountStateTag.STRUCT_TYPE, 0x99)
    payload += format_tlv(TokenAccountStateTag.STRUCT_VERSION, 1)
    payload += format_tlv(TokenAccountStateTag.CHALLENGE, challenge)
    payload += format_tlv(TokenAccountStateTag.ACCOUNT_ADDRESS, b'\x11' * 32)
    payload += format_tlv(TokenAccountStateTag.MINT, b'\x22' * 32)
    payload += format_tlv(TokenAccountStateTag.OWNER, b'\x33' * 32)
    payload += format_tlv(TokenAccountStateTag.PRE_BALANCE, 0)
    payload += format_tlv(TokenAccountStateTag.SIGNATURE, GENERIC_CLEAR_SIGNING_PARTNER.sign(payload))

    sol.send_pki_certificate(GENERIC_CLEAR_SIGNING_PARTNER)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol._exchange_split(CLA, INS.INS_TOKEN_ACCOUNT_STATE, P1_NON_CONFIRM, payload)
    assert exc_info.value.status == ErrorType.INVALID_TOKEN_ACCOUNT_STATE


def test_token_account_state_wrong_version(backend):
    """Sending unsupported version should fail."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    challenge = sol.get_challenge()
    payload = format_tlv(TokenAccountStateTag.STRUCT_TYPE, 0x15)
    payload += format_tlv(TokenAccountStateTag.STRUCT_VERSION, 99)
    payload += format_tlv(TokenAccountStateTag.CHALLENGE, challenge)
    payload += format_tlv(TokenAccountStateTag.ACCOUNT_ADDRESS, b'\x11' * 32)
    payload += format_tlv(TokenAccountStateTag.MINT, b'\x22' * 32)
    payload += format_tlv(TokenAccountStateTag.OWNER, b'\x33' * 32)
    payload += format_tlv(TokenAccountStateTag.PRE_BALANCE, 0)
    payload += format_tlv(TokenAccountStateTag.SIGNATURE, GENERIC_CLEAR_SIGNING_PARTNER.sign(payload))

    sol.send_pki_certificate(GENERIC_CLEAR_SIGNING_PARTNER)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol._exchange_split(CLA, INS.INS_TOKEN_ACCOUNT_STATE, P1_NON_CONFIRM, payload)
    assert exc_info.value.status == ErrorType.INVALID_TOKEN_ACCOUNT_STATE


def test_token_account_state_challenge_consumed(backend):
    """After a successful TOKEN_ACCOUNT_STATE, the challenge should be rolled.
    Reusing the same challenge should fail."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    challenge = sol.get_challenge()
    sol.provide_token_account_state(
        challenge=challenge,
        account_address=b'\x11' * 32,
        mint=b'\x22' * 32,
        owner=b'\x33' * 32,
        pre_balance=0,
    )
    # Second call with the same challenge should fail (challenge was rolled)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_token_account_state(
            challenge=challenge,
            account_address=b'\x11' * 32,
            mint=b'\x22' * 32,
            owner=b'\x33' * 32,
            pre_balance=0,
        )
    assert exc_info.value.status == ErrorType.INVALID_TOKEN_ACCOUNT_STATE


# ── ALT_RESOLUTION ───────────────────────────────────────────────────────────

def test_alt_resolution_valid(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    challenge = sol.get_challenge()
    sol.provide_alt_resolution(
        challenge=challenge,
        alt_address=b'\xaa' * 32,
        entry_index=5,
        resolved_address=b'\xbb' * 32,
    )
    _wipe_session(sol)


def test_alt_resolution_without_session_rejected(backend):
    """ALT_RESOLUTION outside an open streaming session is refused."""
    sol = SolanaClient(backend)
    challenge = sol.get_challenge()
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_alt_resolution(
            challenge=challenge,
            alt_address=b'\xaa' * 32,
            entry_index=0,
            resolved_address=b'\xbb' * 32,
        )
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


def test_alt_resolution_bad_challenge(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.get_challenge()
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_alt_resolution(
            challenge=b'\x00\x00\x00\x00',
            alt_address=b'\xaa' * 32,
            entry_index=0,
            resolved_address=b'\xbb' * 32,
        )
    assert exc_info.value.status == ErrorType.INVALID_ALT_RESOLUTION


def test_alt_resolution_challenge_consumed(backend):
    """After a successful ALT_RESOLUTION, the challenge should be rolled."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    challenge = sol.get_challenge()
    sol.provide_alt_resolution(
        challenge=challenge,
        alt_address=b'\xaa' * 32,
        entry_index=0,
        resolved_address=b'\xbb' * 32,
    )
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_alt_resolution(
            challenge=challenge,
            alt_address=b'\xaa' * 32,
            entry_index=0,
            resolved_address=b'\xbb' * 32,
        )
    assert exc_info.value.status == ErrorType.INVALID_ALT_RESOLUTION


def test_alt_resolution_duplicate_rejected(backend):
    """Providing the same (alt_address, entry_index) twice is refused as a duplicate."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    challenge = sol.get_challenge()
    sol.provide_alt_resolution(
        challenge=challenge,
        alt_address=b'\xaa' * 32,
        entry_index=7,
        resolved_address=b'\xbb' * 32,
    )
    # A fresh challenge, same key: the cache must reject the duplicate.
    challenge = sol.get_challenge()
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_alt_resolution(
            challenge=challenge,
            alt_address=b'\xaa' * 32,
            entry_index=7,
            resolved_address=b'\xcc' * 32,
        )
    assert exc_info.value.status == ErrorType.INVALID_ALT_RESOLUTION


# ── ENUM_VARIANT ─────────────────────────────────────────────────────────────

def test_enum_variant_without_session_rejected(backend):
    """Sending an enum variant outside an open streaming session must fail closed."""
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_enum_variant(
            program_id=b'\x01' * 32,
            enum_id="SwapRoute",
            variant_index=0,
            variant_name="Raydium",
            payload_kind=0x00,  # EMPTY
        )
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


def test_enum_variant_empty_payload(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.provide_enum_variant(
        program_id=b'\x01' * 32,
        enum_id="SwapRoute",
        variant_index=0,
        variant_name="Raydium",
        payload_kind=0x00,  # EMPTY
    )
    _wipe_session(sol)


def test_enum_variant_inline_payload(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.provide_enum_variant(
        program_id=b'\x01' * 32,
        enum_id="SwapRoute",
        variant_index=1,
        variant_name="Orca",
        payload_kind=0x02,  # INLINE
        variant_payload=b'\x05\x01\x02',
    )
    _wipe_session(sol)


def test_enum_variant_long_id_and_name_accepted(backend):
    """enum_id and variant_name well past the removed 64-byte caps are stored,
    proving both fields are now sized to their input."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.provide_enum_variant(
        program_id=b'\x01' * 32,
        enum_id="E" * 200,
        variant_index=0,
        variant_name="N" * 200,
        payload_kind=0x00,  # EMPTY
    )
    _wipe_session(sol)


@pytest.mark.parametrize("field", ["enum_id", "variant_name"])
def test_enum_variant_char_field_embedded_nul_rejected(backend, field):
    """ENUM_ID and VARIANT_NAME are spec char[] fields: an embedded NUL is
    malformed and rejected at ingest, not stored truncated."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    args = dict(
        program_id=b'\x01' * 32,
        enum_id="SwapRoute",
        variant_index=0,
        variant_name="Raydium",
        payload_kind=0x00,  # EMPTY
    )
    args[field] = b"ab\x00cd"  # embedded NUL, sent as raw bytes
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_enum_variant(**args)
    assert exc_info.value.status == ErrorType.INVALID_ENUM_VARIANT


def test_enum_variant_large_inline_payload_accepted(backend):
    """An INLINE payload well past the removed 128-byte cap is stored: the
    descriptor is spec uint8[], sized to its input and bounded only by the pool."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.provide_enum_variant(
        program_id=b'\x01' * 32,
        enum_id="SwapRoute",
        variant_index=1,
        variant_name="Orca",
        payload_kind=0x02,  # INLINE
        variant_payload=b'\x05' * 512,
    )
    _wipe_session(sol)


def test_enum_variant_raw_size_payload(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.provide_enum_variant(
        program_id=b'\x01' * 32,
        enum_id="SwapRoute",
        variant_index=2,
        variant_name="Jupiter",
        payload_kind=0x03,  # RAW_SIZE
        variant_payload=b'\x00\x10',  # 16 bytes
    )
    _wipe_session(sol)


def test_enum_variant_bad_payload_kind(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_enum_variant(
            program_id=b'\x01' * 32,
            enum_id="SwapRoute",
            variant_index=0,
            variant_name="Bad",
            payload_kind=0xFF,  # unknown
        )
    assert exc_info.value.status == ErrorType.INVALID_ENUM_VARIANT


def test_enum_variant_empty_with_payload_rejected(backend):
    """EMPTY payload_kind must not have a PAYLOAD tag."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_enum_variant(
            program_id=b'\x01' * 32,
            enum_id="SwapRoute",
            variant_index=0,
            variant_name="Bad",
            payload_kind=0x00,  # EMPTY
            variant_payload=b'\x01\x02\x03',
        )
    assert exc_info.value.status == ErrorType.INVALID_ENUM_VARIANT


def test_enum_variant_inline_without_payload_rejected(backend):
    """INLINE payload_kind requires a PAYLOAD tag."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_enum_variant(
            program_id=b'\x01' * 32,
            enum_id="SwapRoute",
            variant_index=0,
            variant_name="Bad",
            payload_kind=0x02,  # INLINE
            # no variant_payload
        )
    assert exc_info.value.status == ErrorType.INVALID_ENUM_VARIANT


def test_enum_variant_raw_size_wrong_length_rejected(backend):
    """RAW_SIZE payload must be exactly 2 bytes."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_enum_variant(
            program_id=b'\x01' * 32,
            enum_id="SwapRoute",
            variant_index=0,
            variant_name="Bad",
            payload_kind=0x03,  # RAW_SIZE
            variant_payload=b'\x00\x10\x20',  # 3 bytes, should be 2
        )
    assert exc_info.value.status == ErrorType.INVALID_ENUM_VARIANT


# ── INSTRUCTION_INFO ─────────────────────────────────────────────────────────

def test_instruction_info_valid_minimal(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.provide_instruction_info(
        program_id=b'\x01' * 32,
        discriminator=b'\xab\xcd\xef\x01',
        operation_type="Transfer",
        substructures_hash=b'\x00' * 32,
        idl_type_pool=b'\x01\x02\x03',
        idl_root_type=0,
    )
    _wipe_session(sol)


def test_instruction_info_long_names_accepted(backend):
    """OPERATION_TYPE and PROGRAM_NAME are stored in right-sized heap buffers, so
    long names (well beyond the former 31-char buffers) are accepted verbatim."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.provide_instruction_info(
        program_id=b'\x01' * 32,
        discriminator=b'\xab\xcd\xef\x01',
        operation_type="O" * 100,
        program_name="P" * 100,
        substructures_hash=b'\x00' * 32,
        idl_type_pool=b'\x01\x02\x03',
        idl_root_type=0,
    )
    _wipe_session(sol)


def test_instruction_info_with_mint_assoc(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    sol.provide_instruction_info(
        program_id=b'\x02' * 32,
        discriminator=b'\x01\x02',
        operation_type="Swap",
        program_name="Jupiter",
        substructures_hash=b'\xaa' * 32,
        idl_type_pool=b'\x01',
        idl_root_type=0,
        mint_assoc_account=3,
        mint_assoc_mint=4,
    )
    _wipe_session(sol)


def test_instruction_info_mint_assoc_incomplete(backend):
    """MINT_ASSOC_ACCOUNT without MINT_ASSOC_MINT should fail.
    Without an active CS session, the state machine rejects the APDU first."""
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_info(
            program_id=b'\x02' * 32,
            operation_type="Bad",
            substructures_hash=b'\x00' * 32,
            idl_type_pool=b'\x01',
            idl_root_type=0,
            mint_assoc_account=3,
            # mint_assoc_mint intentionally omitted
        )
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


def test_instruction_info_owner_assoc_incomplete(backend):
    """OWNER_ASSOC_ACCOUNT without OWNER_ASSOC_OWNER should fail.
    Without an active CS session, the state machine rejects the APDU first."""
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_info(
            program_id=b'\x02' * 32,
            operation_type="Bad",
            substructures_hash=b'\x00' * 32,
            idl_type_pool=b'\x01',
            idl_root_type=0,
            owner_assoc_account=5,
            # owner_assoc_owner_value intentionally omitted
        )
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


def test_instruction_info_with_owner_assoc(backend):
    """OWNER_ASSOC_ACCOUNT + OWNER_ASSOC_OWNER (VALUE sub-TLV)."""
    sol = SolanaClient(backend)
    _begin_session(sol, _craft_single_instruction_message(sol, b'\x05' * 32, b'\x00'))
    # Build a VALUE sub-TLV: ACCOUNT_PATH source, account index 2
    value_sub_tlv = format_tlv(ValueTag.SOURCE, 0x01) + format_tlv(ValueTag.PAYLOAD, b'\x02')
    sol.provide_instruction_info(
        program_id=b'\x03' * 32,
        operation_type="Transfer",
        substructures_hash=b'\x00' * 32,
        idl_type_pool=b'\x01',
        idl_root_type=0,
        owner_assoc_account=5,
        owner_assoc_owner_value=value_sub_tlv,
    )
    _wipe_session(sol)


# ── BRIDGE: GENERIC PREVIEW → INFO → SUBSTRUCTURE → PROMPT UI DISPLAY ─────────

# Synthetic program whose single instruction argument struct is {u32, u64},
# preceded by a 1-byte discriminator consumed by a BYTES_FIXED root field.
BRIDGE_PROGRAM_ID = b'\x07' * 32
BRIDGE_DISCRIMINATOR = b'\x07'

# IDL type pool: u8 count || entries.
#   [0] STRUCT(0x20) field_count=3 refs=[1,2,3]
#   [1] BYTES_FIXED(0x12) fixed_size=1   (consumes the discriminator)
#   [2] U32(0x03)
#   [3] U64(0x04)
BRIDGE_POOL = bytes([4, 0x20, 3, 1, 2, 3, 0x12, 0x00, 0x01, 0x03, 0x04])

# Packed argument paths (u8 step_count || packed steps); STRUCT steps are 1 byte.
BRIDGE_PATH_DISC = b'\x01\x00'
BRIDGE_PATH_U32 = b'\x01\x01'
BRIDGE_PATH_U64 = b'\x01\x02'


def _bridge_instruction_data(u32_value: int, u64_value: int) -> bytes:
    return BRIDGE_DISCRIMINATOR + struct.pack("<I", u32_value) + struct.pack("<Q", u64_value)


def test_bridge_walks_instruction(backend, sol, scenario_navigator, root_pytest_dir):
    """End-to-end MVP bridge: the walker decodes the synthetic instruction,
    the display renderer formats the u32 leaf, and NBGL review is navigated."""

    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_bridge_amount_max_label_accepted(backend, sol):
    """A PARAM_AMOUNT descriptor carrying the optional MAX_LABEL tag is accepted by
    the substructure parser (previously an unregistered tag aborted the session)
    and the session finalizes with the u64 leaf at its type maximum."""
    message = _craft_single_instruction_message(
        sol, BRIDGE_PROGRAM_ID, _bridge_instruction_data(1000, 0xFFFFFFFFFFFFFFFF))
    _begin_session(sol, message)

    display_field = _build_amount_display_field(BRIDGE_PATH_U64, 9, "Amount",
                                                max_label="Unlimited")
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Approve",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


def test_bridge_token_amount_max_label_accepted(backend, sol):
    """A PARAM_TOKEN_AMOUNT descriptor carrying the optional MAX_LABEL tag is
    accepted by the substructure parser and the session finalizes."""
    message = _craft_single_instruction_message(
        sol, BRIDGE_PROGRAM_ID, _bridge_instruction_data(1000, 0xFFFFFFFFFFFFFFFF))
    _begin_session(sol, message)

    display_field = _build_token_amount_display_field(BRIDGE_PATH_U64, True, "Amount",
                                                      max_label="Unlimited")
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Approve",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


def _build_value_flow_port(*, account_index: int, amount_path: bytes,
                           value_kind: int = PORT_VALUE_KIND_NATIVE,
                           direction: int = PORT_DIRECTION_OUTPUT) -> bytes:
    """A VALUE_FLOW_PORT: one account candidate, a NUMERIC amount read from an
    ARGUMENT_PATH leaf, and a native value kind (no token)."""
    amount_value = (format_tlv(AMOUNT_VALUE_TAG_KIND, AMOUNT_KIND_NUMERIC)
                    + format_tlv(AMOUNT_VALUE_TAG_VALUE,
                                 format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                                 + format_tlv(ValueTag.PAYLOAD, amount_path)))
    return (format_tlv(VFP_TAG_VERSION, 1)
            + format_tlv(VFP_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT)
            + format_tlv(VFP_TAG_DIRECTION, direction)
            + format_tlv(VFP_TAG_ACCOUNT_INDEX, account_index)
            + format_tlv(VFP_TAG_VALUE_KIND, value_kind)
            + format_tlv(VFP_TAG_AMOUNT_VALUE, amount_value))


def _build_balance_port(*, account_index: int, value_kind: int, direction: int,
                        token_account_index: int = None) -> bytes:
    """A VALUE_FLOW_PORT whose amount is the symbolic whole balance of the account,
    optionally carrying a DIRECT token whose mint is read from the accounts array."""
    amount_value = format_tlv(AMOUNT_VALUE_TAG_KIND, AMOUNT_KIND_BALANCE)
    payload = (format_tlv(VFP_TAG_VERSION, 1)
               + format_tlv(VFP_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT)
               + format_tlv(VFP_TAG_DIRECTION, direction)
               + format_tlv(VFP_TAG_ACCOUNT_INDEX, account_index)
               + format_tlv(VFP_TAG_VALUE_KIND, value_kind)
               + format_tlv(VFP_TAG_AMOUNT_VALUE, amount_value))
    if token_account_index is not None:
        token_value = (format_tlv(TOKEN_VALUE_TAG_KIND, TOKEN_KIND_DIRECT)
                       + format_tlv(TOKEN_VALUE_TAG_VALUE,
                                    format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ACCOUNT_PATH)
                                    + format_tlv(ValueTag.PAYLOAD,
                                                 bytes([token_account_index]))))
        payload += format_tlv(VFP_TAG_TOKEN_VALUE, token_value)
    return payload


def _build_constant_amount_port(*, account_index: int, amount: int, direction: int) -> bytes:
    """A VALUE_FLOW_PORT carrying a literal little-endian u64 amount and no token,
    the shape a descriptor uses to declare an account coming into existence."""
    amount_value = (format_tlv(AMOUNT_VALUE_TAG_KIND, AMOUNT_KIND_NUMERIC)
                    + format_tlv(AMOUNT_VALUE_TAG_VALUE,
                                 format_tlv(ValueTag.SOURCE, VALUE_SOURCE_CONSTANT)
                                 + format_tlv(ValueTag.PAYLOAD, struct.pack("<Q", amount))))
    return (format_tlv(VFP_TAG_VERSION, 1)
            + format_tlv(VFP_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT)
            + format_tlv(VFP_TAG_DIRECTION, direction)
            + format_tlv(VFP_TAG_ACCOUNT_INDEX, account_index)
            + format_tlv(VFP_TAG_VALUE_KIND, PORT_VALUE_KIND_NATIVE)
            + format_tlv(VFP_TAG_AMOUNT_VALUE, amount_value))


def _build_hide_rule(*, target_account_index: int, condition: int = HIDE_CONDITION_IS_SIGNER,
                     rule_set_index: int = 0) -> bytes:
    """A HIDE_RULE whose target is a pubkey-resolving ACCOUNT_PATH VALUE."""
    target = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ACCOUNT_PATH)
              + format_tlv(ValueTag.PAYLOAD, bytes([target_account_index])))
    return (format_tlv(HIDE_RULE_TAG_VERSION, 1)
            + format_tlv(HIDE_RULE_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_HIDE_RULE)
            + format_tlv(HIDE_RULE_TAG_RULE_SET_INDEX, rule_set_index)
            + format_tlv(HIDE_RULE_TAG_TARGET, target)
            + format_tlv(HIDE_RULE_TAG_CONDITION, condition))


def _build_account_reset(*, account_index: int, require_zero: bool = True,
                         reset_constant: bytes = None, scope_program_id: bytes = None,
                         scope_discriminators: list = None) -> bytes:
    """An ACCOUNT_RESET with an optional CONSTANT reset value and RESET_SCOPE."""
    payload = (format_tlv(ACCOUNT_RESET_TAG_VERSION, 1)
               + format_tlv(ACCOUNT_RESET_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_ACCOUNT_RESET)
               + format_tlv(ACCOUNT_RESET_TAG_ACCOUNT_INDEX, account_index)
               + format_tlv(ACCOUNT_RESET_TAG_REQUIRE_ZERO, 1 if require_zero else 0))
    if reset_constant is not None:
        reset_value = (format_tlv(AMOUNT_VALUE_TAG_KIND, AMOUNT_KIND_NUMERIC)
                       + format_tlv(AMOUNT_VALUE_TAG_VALUE,
                                    format_tlv(ValueTag.SOURCE, VALUE_SOURCE_CONSTANT)
                                    + format_tlv(ValueTag.PAYLOAD, reset_constant)))
        payload += format_tlv(ACCOUNT_RESET_TAG_RESET_VALUE, reset_value)
    if scope_program_id is not None:
        scope = format_tlv(RESET_SCOPE_TAG_PROGRAM_ID, scope_program_id)
        for disc in (scope_discriminators or []):
            scope += format_tlv(RESET_SCOPE_TAG_DISCRIMINATOR, disc)
        payload += format_tlv(ACCOUNT_RESET_TAG_RESET_SCOPE, scope)
    return payload


def test_cs_value_flow_port_forwarded(backend, sol):
    """A DISPLAY_FIELD plus a VALUE_FLOW_PORT: the port is decoded and its account
    and ARGUMENT_PATH amount resolve during the walk/render. A lone instruction has
    no counterpart to form a junction with, so it is displayed as is."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    port = _build_value_flow_port(account_index=0, amount_path=BRIDGE_PATH_U64)
    substructures_hash = hashlib.sha256(display_field + port).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, port)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


def test_cs_hide_rule_hides_instruction(backend, sol):
    """A HIDE_RULE whose isSigner condition holds for its target hides the instruction
    post-merge. Account 0 is the device signer, so the rule fires; with the sole
    instruction hidden the review has nothing to show and PROMPT UI DISPLAY reports
    CLEAR_SIGNING_INCOMPLETE."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    hide_rule = _build_hide_rule(target_account_index=0)
    substructures_hash = hashlib.sha256(display_field + hide_rule).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_HIDE_RULE, hide_rule)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.prompt_ui_display()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INCOMPLETE
    _wipe_session(sol)


def test_cs_hide_rule_not_triggered_shows_instruction(backend, sol, scenario_navigator,
                                                      root_pytest_dir):
    """The same isSigner HIDE_RULE aimed at a non-signer account does not fire, so the
    instruction survives and PROMPT UI DISPLAY produces its review instead of reporting
    CLEAR_SIGNING_INCOMPLETE."""
    other_account = bytes(Pubkey.from_string("4K2V1kpVycZ6qSFsNdz2FtpNxnJs17eBNzf9rdCMcKoe"))
    message = _craft_instruction_with_accounts(sol,
                                               BRIDGE_PROGRAM_ID,
                                               _bridge_instruction_data(1000, 5_000_000),
                                               [other_account])
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    # Account 1 is the extra non-signer, so isSigner fails and the instruction stays visible.
    hide_rule = _build_hide_rule(target_account_index=1)
    substructures_hash = hashlib.sha256(display_field + hide_rule).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_HIDE_RULE, hide_rule)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_account_reset_forwarded(backend, sol):
    """An ACCOUNT_RESET with a CONSTANT reset value and a RESET_SCOPE (program id +
    discriminator) is decoded, its account resolves, and the session finalizes."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    account_reset = _build_account_reset(account_index=0,
                                         reset_constant=struct.pack("<Q", 0),
                                         scope_program_id=BRIDGE_PROGRAM_ID,
                                         scope_discriminators=[BRIDGE_DISCRIMINATOR])
    substructures_hash = hashlib.sha256(display_field + account_reset).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_ACCOUNT_RESET, account_reset)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


# ── Merge engine end-to-end: a symbolic-junction chain ────────────────────────
#
# Three programs standing in for the wrap pattern that dominates real Solana
# transactions:
#
#   create    declares the junction account coming into existence, empty
#   transfer  moves a concrete amount from the signer into the junction
#   wrap      drains the junction's whole balance and re-declares it as a token
#
# The wrap names no amount, so the device may only fold it into the transfer when
# the create's ACCOUNT_RESET vouches for the junction having started empty. Each
# test below removes one part of that proof and checks the review follows.

CHAIN_CREATE_PROGRAM_ID = b'\x31' * 32
CHAIN_CREATE_DISCRIMINATOR = b'\x31'
CHAIN_TRANSFER_PROGRAM_ID = b'\x32' * 32
CHAIN_TRANSFER_DISCRIMINATOR = b'\x32'
CHAIN_WRAP_PROGRAM_ID = b'\x33' * 32
CHAIN_WRAP_DISCRIMINATOR = b'\x33'

# IDL type pool for an instruction whose data is only its discriminator:
#   [0] STRUCT(0x20) field_count=1 refs=[1]
#   [1] BYTES_FIXED(0x12) fixed_size=1
CHAIN_DISCRIMINATOR_ONLY_POOL = bytes([2, 0x20, 1, 1, 0x12, 0x00, 0x01])

# IDL type pool for discriminator || u64 amount.
#   [0] STRUCT(0x20) field_count=2 refs=[1,2]
#   [1] BYTES_FIXED(0x12) fixed_size=1
#   [2] U64(0x04)
CHAIN_TRANSFER_POOL = bytes([3, 0x20, 2, 1, 2, 0x12, 0x00, 0x01, 0x04])
CHAIN_TRANSFER_PATH_AMOUNT = b'\x01\x01'

CHAIN_TRANSFER_AMOUNT = 5_000_000
CHAIN_JUNCTION = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
CHAIN_MINT = bytes(Pubkey.from_string("So11111111111111111111111111111111111111112"))
# Owner attested alongside the junction's pre-balance. Only the pre-balance bears on
# the merge, so this is any address; it must not be fetched from the device, since an
# unrelated instruction mid-session abandons the clear-signing session.
CHAIN_OWNER = bytes(Pubkey.from_string("4K2V1kpVycZ6qSFsNdz2FtpNxnJs17eBNzf9rdCMcKoe"))

# Slot layout shared by the three instructions: the signer, then the junction, then
# the mint. Every instruction lists the slots it references, in this order.
CHAIN_SLOT_SIGNER = 0
CHAIN_SLOT_JUNCTION = 1
CHAIN_SLOT_MINT = 2


def _craft_chain_message(sol: SolanaClient) -> bytes:
    """The three-instruction message the merge-chain tests share."""
    sender = Pubkey.from_bytes(sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH))
    signer_meta = AccountMeta(pubkey=sender, is_signer=True, is_writable=True)
    junction_meta = AccountMeta(pubkey=Pubkey.from_bytes(CHAIN_JUNCTION),
                                is_signer=False, is_writable=True)
    mint_meta = AccountMeta(pubkey=Pubkey.from_bytes(CHAIN_MINT),
                            is_signer=False, is_writable=False)

    create = Instruction(
        program_id=Pubkey.from_bytes(CHAIN_CREATE_PROGRAM_ID),
        accounts=[signer_meta, junction_meta],
        data=CHAIN_CREATE_DISCRIMINATOR,
    )
    transfer = Instruction(
        program_id=Pubkey.from_bytes(CHAIN_TRANSFER_PROGRAM_ID),
        accounts=[signer_meta, junction_meta],
        data=CHAIN_TRANSFER_DISCRIMINATOR + struct.pack("<Q", CHAIN_TRANSFER_AMOUNT),
    )
    wrap = Instruction(
        program_id=Pubkey.from_bytes(CHAIN_WRAP_PROGRAM_ID),
        accounts=[signer_meta, junction_meta, mint_meta],
        data=CHAIN_WRAP_DISCRIMINATOR,
    )
    return sol.craft_tx([create, transfer, wrap], sender)


def _provide_chain_create(sol: SolanaClient, *, reset: bytes = None) -> None:
    """The create instruction: an output port declaring the junction empty, plus the
    ACCOUNT_RESET that vouches for it. `reset` omitted means no reset is declared."""
    port = _build_constant_amount_port(account_index=CHAIN_SLOT_JUNCTION, amount=0,
                                       direction=PORT_DIRECTION_OUTPUT)
    account_field = _build_account_display_field(CHAIN_SLOT_JUNCTION, "Account")
    substructures = account_field + port
    if reset is not None:
        substructures += reset

    sol.provide_instruction_info(
        program_id=CHAIN_CREATE_PROGRAM_ID,
        discriminator=CHAIN_CREATE_DISCRIMINATOR,
        operation_type="Create account",
        program_name="Chain",
        substructures_hash=hashlib.sha256(substructures).digest(),
        idl_type_pool=CHAIN_DISCRIMINATOR_ONLY_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, account_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, port)
    if reset is not None:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_ACCOUNT_RESET, reset)


def _provide_chain_transfer(sol: SolanaClient) -> None:
    """The transfer instruction: signer in, junction out, both at the amount its
    instruction data carries. Its destination field is what the merge rewrites."""
    amount_field = _build_amount_display_field(CHAIN_TRANSFER_PATH_AMOUNT, 9, "Amount")
    destination_field = _build_account_display_field(CHAIN_SLOT_JUNCTION, "To")
    input_port = _build_value_flow_port(account_index=CHAIN_SLOT_SIGNER,
                                       amount_path=CHAIN_TRANSFER_PATH_AMOUNT,
                                       direction=PORT_DIRECTION_INPUT)
    output_port = _build_value_flow_port(account_index=CHAIN_SLOT_JUNCTION,
                                        amount_path=CHAIN_TRANSFER_PATH_AMOUNT,
                                        direction=PORT_DIRECTION_OUTPUT)
    substructures = amount_field + destination_field + input_port + output_port

    sol.provide_instruction_info(
        program_id=CHAIN_TRANSFER_PROGRAM_ID,
        discriminator=CHAIN_TRANSFER_DISCRIMINATOR,
        operation_type="Send",
        program_name="Chain",
        substructures_hash=hashlib.sha256(substructures).digest(),
        idl_type_pool=CHAIN_TRANSFER_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, amount_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, destination_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, input_port)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, output_port)


def _provide_chain_wrap(sol: SolanaClient) -> None:
    """The wrap instruction: it drains and refills the junction's whole balance,
    changing the form of the value without naming an amount."""
    account_field = _build_account_display_field(CHAIN_SLOT_JUNCTION, "Account")
    input_port = _build_balance_port(account_index=CHAIN_SLOT_JUNCTION,
                                     value_kind=PORT_VALUE_KIND_NATIVE,
                                     direction=PORT_DIRECTION_INPUT)
    output_port = _build_balance_port(account_index=CHAIN_SLOT_JUNCTION,
                                      value_kind=PORT_VALUE_KIND_SPL_TOKEN,
                                      direction=PORT_DIRECTION_OUTPUT,
                                      token_account_index=CHAIN_SLOT_MINT)
    substructures = account_field + input_port + output_port

    sol.provide_instruction_info(
        program_id=CHAIN_WRAP_PROGRAM_ID,
        discriminator=CHAIN_WRAP_DISCRIMINATOR,
        operation_type="Wrap",
        program_name="Chain",
        substructures_hash=hashlib.sha256(substructures).digest(),
        idl_type_pool=CHAIN_DISCRIMINATOR_ONLY_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, account_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, input_port)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, output_port)


def _provide_chain(sol: SolanaClient, *, reset: bytes = None) -> None:
    _provide_chain_create(sol, reset=reset)
    _provide_chain_transfer(sol)
    _provide_chain_wrap(sol)


def test_cs_symbolic_junction_collapses(backend, sol, scenario_navigator, root_pytest_dir):
    """The create's ACCOUNT_RESET vouches for the junction starting empty, so the
    whole balance the wrap moves is exactly what the transfer put there. The wrap is
    folded into the transfer and the review shows two screens instead of three."""
    _begin_session(sol, _craft_chain_message(sol))
    _provide_chain(sol, reset=_build_account_reset(account_index=CHAIN_SLOT_JUNCTION,
                                                  require_zero=False))

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_symbolic_junction_without_reset_shows_both(backend, sol, scenario_navigator,
                                                       root_pytest_dir):
    """Without an ACCOUNT_RESET nothing states what the junction held before the
    transfer, so the amount the wrap moves is unknown and both instructions are
    reviewed on their own screens."""
    _begin_session(sol, _craft_chain_message(sol))
    _provide_chain(sol)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_symbolic_junction_reset_scope_mismatch_shows_both(backend, sol, scenario_navigator,
                                                              root_pytest_dir):
    """A RESET_SCOPE naming another program does not vouch for the wrap, so the
    collapse is refused and both instructions are reviewed."""
    _begin_session(sol, _craft_chain_message(sol))
    _provide_chain(sol, reset=_build_account_reset(account_index=CHAIN_SLOT_JUNCTION,
                                                  require_zero=False,
                                                  scope_program_id=CHAIN_TRANSFER_PROGRAM_ID))

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_symbolic_junction_reset_scope_match_collapses(backend, sol, scenario_navigator,
                                                          root_pytest_dir):
    """A RESET_SCOPE naming the wrap's program and discriminator prefix vouches for
    it, so the collapse stands."""
    _begin_session(sol, _craft_chain_message(sol))
    _provide_chain(sol, reset=_build_account_reset(
        account_index=CHAIN_SLOT_JUNCTION,
        require_zero=False,
        scope_program_id=CHAIN_WRAP_PROGRAM_ID,
        scope_discriminators=[CHAIN_WRAP_DISCRIMINATOR]))

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_symbolic_junction_pre_balance_zero_needs_attestation(backend, sol,
                                                                 scenario_navigator,
                                                                 root_pytest_dir):
    """A reset carrying REQUIRE_PRE_BALANCE_ZERO obliges the device to read the
    account's attested pre-balance. With no TOKEN_ACCOUNT_STATE for the junction
    there is nothing to read, so the reset vouches for nothing and both
    instructions are reviewed."""
    _begin_session(sol, _craft_chain_message(sol))
    _provide_chain(sol, reset=_build_account_reset(account_index=CHAIN_SLOT_JUNCTION,
                                                  require_zero=True))

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_symbolic_junction_pre_balance_zero_attested_collapses(backend, sol,
                                                                  scenario_navigator,
                                                                  root_pytest_dir):
    """The same reset with an attested zero pre-balance for the junction: the
    precondition holds, so the collapse stands."""
    _begin_session(sol, _craft_chain_message(sol))
    sol.provide_token_account_state(challenge=sol.get_challenge(),
                                    account_address=CHAIN_JUNCTION,
                                    mint=CHAIN_MINT,
                                    owner=sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH),
                                    pre_balance=0)
    _provide_chain(sol, reset=_build_account_reset(account_index=CHAIN_SLOT_JUNCTION,
                                                  require_zero=True))

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_symbolic_junction_pre_balance_non_zero_shows_both(backend, sol,
                                                              scenario_navigator,
                                                              root_pytest_dir):
    """An attested non-zero pre-balance contradicts REQUIRE_PRE_BALANCE_ZERO: the
    junction already held value the reset does not account for, so both
    instructions are reviewed."""
    _begin_session(sol, _craft_chain_message(sol))
    sol.provide_token_account_state(challenge=sol.get_challenge(),
                                    account_address=CHAIN_JUNCTION,
                                    mint=CHAIN_MINT,
                                    owner=sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH),
                                    pre_balance=42)
    _provide_chain(sol, reset=_build_account_reset(account_index=CHAIN_SLOT_JUNCTION,
                                                  require_zero=True))

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_symbolic_junction_collapse_rejected(backend, sol, scenario_navigator,
                                                root_pytest_dir):
    """The collapsed review is rejected: the app refuses to sign."""
    _begin_session(sol, _craft_chain_message(sol))
    _provide_chain(sol, reset=_build_account_reset(account_index=CHAIN_SLOT_JUNCTION,
                                                  require_zero=False))

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with pytest.raises(ExceptionRAPDU) as exc_info:
        with sol.send_prompt_ui_display():
            scenario_navigator.review_reject(path=root_pytest_dir)
    assert exc_info.value.status == ErrorType.USER_CANCEL
    _wipe_session(sol)


@pytest.mark.parametrize("constant_width", [3, 5, 16])
def test_cs_amount_constant_odd_width_rejected(backend, sol, constant_width):
    """An AMOUNT_VALUE CONSTANT carries no kind of its own, so its byte count is the
    only thing that says how wide the number is. A count that is not an integer width
    describes no number, which makes the descriptor malformed: the substructure is
    refused on arrival rather than stored as an amount nothing can read."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    account_reset = _build_account_reset(account_index=0,
                                         require_zero=False,
                                         reset_constant=bytes(constant_width))
    substructures_hash = hashlib.sha256(display_field + account_reset).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_ACCOUNT_RESET, account_reset)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE
    _wipe_session(sol)


def test_cs_amount_constant_integer_widths_accepted(backend, sol):
    """The four integer widths a constant amount may carry are all accepted."""
    for constant_width in (1, 2, 4, 8):
        message = _craft_single_instruction_message(sol,
                                                    BRIDGE_PROGRAM_ID,
                                                    _bridge_instruction_data(1000, 5_000_000))
        _begin_session(sol, message)

        display_field = _build_display_field(BRIDGE_PATH_U32)
        account_reset = _build_account_reset(account_index=0,
                                             require_zero=False,
                                             reset_constant=bytes(constant_width))
        substructures_hash = hashlib.sha256(display_field + account_reset).digest()

        sol.provide_instruction_info(
            program_id=BRIDGE_PROGRAM_ID,
            discriminator=BRIDGE_DISCRIMINATOR,
            operation_type="Transfer",
            program_name="Bridge",
            substructures_hash=substructures_hash,
            idl_type_pool=BRIDGE_POOL,
            idl_root_type=0,
        )
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_ACCOUNT_RESET, account_reset)

        assert sol.finalize_generic_clear_signing().status == 0x9000
        _wipe_session(sol)


def test_cs_twenty_instructions_finalize(backend, sol):
    """Twenty instructions sharing one template walk, merge and render. The dynamic
    pool bounds how far this scales: measured on Flex, the display renderer runs out
    of room building elements somewhere around the thirtieth instruction, well before
    the merge engine's own scratch becomes the binding allocation. This pins a count
    comfortably inside that range so a heavier per-instruction footprint shows up."""
    message = _craft_multi_instruction_message(sol, ALT_PROGRAM_ID, ALT_DISCRIMINATOR, 20)
    _begin_session(sol, message)

    display_field = _build_account_display_field(0, "Account")
    sol.provide_instruction_info(
        program_id=ALT_PROGRAM_ID,
        discriminator=ALT_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="AltProg",
        substructures_hash=hashlib.sha256(display_field).digest(),
        idl_type_pool=ALT_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    _wipe_session(sol)


def test_cs_owner_assoc_forwarded(backend, sol):
    """OWNER_ASSOC on the INSTRUCTION_INFO is stored and its owner (an ACCOUNT_PATH
    VALUE) plus token account resolve into the owner-binding map at finalize."""
    owner_pubkey = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
    message = _craft_instruction_with_accounts(
        sol,
        BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(1000, 5_000_000),
        extra_accounts=[owner_pubkey],
    )
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(display_field).digest()

    # OWNER_ASSOC_ACCOUNT = token account index 0, OWNER = ACCOUNT_PATH index 1.
    owner_value = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ACCOUNT_PATH)
                   + format_tlv(ValueTag.PAYLOAD, bytes([1])))
    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
        owner_assoc_account=0,
        owner_assoc_owner_value=owner_value,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


def test_cs_unknown_substructure_type_rejected(backend, sol):
    """An unknown substructure type byte is refused even though its bytes still
    fold into the substructure hash."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(0x7F, display_field)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE
    _wipe_session(sol)


def test_cs_more_instructions_than_old_template_cap(backend, sol):
    """Regression: five instructions sharing one template. The removed
    CS_MAX_INSTRUCTION_TEMPLATES (4) cap falsely rejected this at finalize; the
    walk buffers are now sized to the real instruction count, so it succeeds."""
    data = _bridge_instruction_data(1000, 5_000_000)
    message = _craft_multi_instruction_message(sol, BRIDGE_PROGRAM_ID, data, 5)
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


def test_cs_more_display_fields_than_old_cap(backend, sol):
    """Regression: a template carrying twelve display fields (one ARGUMENT_PATH
    plus eleven CONSTANTs). The removed CS_MAX_DISPLAY_FIELDS (8) cap falsely
    refused this; the demand-grown field array and the field-count-sized walk
    buffers now assemble, walk and render it."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    fields = [_build_display_field(BRIDGE_PATH_U32)]
    for i in range(11):
        fields.append(_build_constant_display_field(struct.pack("<I", i), IDL_KIND_U32, f"Const{i}"))
    substructures_hash = hashlib.sha256(b"".join(fields)).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    for field in fields:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


def test_bridge_with_account_path_field(backend, sol, scenario_navigator, root_pytest_dir):
    """An instruction with both ARGUMENT_PATH and ACCOUNT_PATH display fields.
    The ACCOUNT_PATH field should resolve to the base58 pubkey of the referenced account."""

    destination_pubkey = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
    message = _craft_instruction_with_accounts(
        sol,
        BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(42, 7_000_000),
        extra_accounts=[destination_pubkey],
    )
    _begin_session(sol, message)

    # Two display fields: first an ACCOUNT_PATH (account index 1 = destination),
    # then an ARGUMENT_PATH (the u32 value from instruction data).
    account_field = _build_account_display_field(1, "Destination")
    argument_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(account_field + argument_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, account_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, argument_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_bridge_with_constant_field(backend, sol, scenario_navigator, root_pytest_dir):
    """An instruction with an ARGUMENT_PATH and a CONSTANT display field.
    The CONSTANT field carries a u32 value (99) embedded in the descriptor,
    rendered via format_leaf using its IDL kind (U32)."""

    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    # Two display fields: an ARGUMENT_PATH (u32 from instruction data),
    # then a CONSTANT (u32 value 99 embedded in the descriptor).
    argument_field = _build_display_field(BRIDGE_PATH_U32)
    constant_field = _build_constant_display_field(struct.pack("<I", 99), IDL_KIND_U32, "Fee")
    substructures_hash = hashlib.sha256(argument_field + constant_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, argument_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, constant_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_bridge_raw_scalar_kinds(backend, sol, scenario_navigator, root_pytest_dir):
    """Every RAW scalar kind that format_leaf must render, embedded as CONSTANT
    display fields: signed integers, 128-bit integers, floats, a multi-byte
    compact-u16, a multi-byte bool and raw bytes-as-hex."""

    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    fields = [
        _build_constant_display_field(struct.pack("<q", -1234567), IDL_KIND_I64, "I64"),
        _build_constant_display_field((2 ** 100).to_bytes(16, "little"), IDL_KIND_U128, "U128"),
        _build_constant_display_field((-(2 ** 100)).to_bytes(16, "little", signed=True),
                                      IDL_KIND_I128, "I128"),
        _build_constant_display_field(struct.pack("<f", -2.5), IDL_KIND_F32, "F32"),
        _build_constant_display_field(struct.pack("<d", 1.5), IDL_KIND_F64, "F64"),
        _build_constant_display_field(b'\xac\x02', IDL_KIND_SHORT_U16, "ShortU16"),
        _build_constant_display_field(b'\x00\x01', IDL_KIND_BOOL_U16, "BoolU16"),
        _build_constant_display_field(b'\xde\xad\xbe\xef', IDL_KIND_BYTES_FIXED, "Bytes"),
    ]
    substructures_hash = hashlib.sha256(b"".join(fields)).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    for field in fields:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_bridge_prompt_without_complete_substructures_rejected(backend):
    """FINALIZE before the substructure stream matches SUBSTRUCTURES_HASH
    must fail closed."""
    sol = SolanaClient(backend)

    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    # No substructure provided: the template never completes.
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INCOMPLETE


def test_bridge_prompt_without_session_rejected(backend):
    """PROMPT UI DISPLAY with no open session must fail closed."""
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.prompt_ui_display()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


def test_finalize_without_session_rejected(backend):
    """FINALIZE GENERIC CLEAR SIGNING with no open session must fail closed."""
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


def test_prompt_without_finalize_rejected(backend):
    """PROMPT UI DISPLAY without prior FINALIZE must fail closed."""
    sol = SolanaClient(backend)

    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(display_field).digest()  # noqa: F841

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    # Skip FINALIZE, go straight to PROMPT — must be rejected
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.prompt_ui_display()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


def test_substruct_type_mismatch_rejected(backend):
    """SUBSTRUCT_TYPE in the TLV must match the APDU type byte."""
    sol = SolanaClient(backend)

    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        substructures_hash=b'\x00' * 32,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    # Build a DISPLAY_FIELD with SUBSTRUCT_TYPE=0x01 (VALUE_FLOW_PORT) mismatch
    value_tlv = (format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ARGUMENT_PATH)
                 + format_tlv(ValueTag.PAYLOAD, BRIDGE_PATH_U32))
    param_raw = (format_tlv(PARAM_TAG_VERSION, 1)
                 + format_tlv(PARAM_TAG_VALUE, value_tlv))
    bad_display_field = (format_tlv(DISPLAY_FIELD_TAG_VERSION, 1)
                         + format_tlv(DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, 0x01)  # wrong!
                         + format_tlv(DISPLAY_FIELD_TAG_NAME, "Amount")
                         + format_tlv(DISPLAY_FIELD_TAG_PARAM_TYPE, PARAM_TYPE_RAW)
                         + format_tlv(DISPLAY_FIELD_TAG_PARAM, param_raw))

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, bad_display_field)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE


# ── PARAM_TYPE formatting tests ──────────────────────────────────────────────

def test_bridge_amount_with_decimals(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_AMOUNT: a u64 value with 9 decimals displays as scaled amount."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 1_000_000_000))
    _begin_session(sol, message)

    # Path to the u64 field (index 2 in the struct)
    display_field = _build_amount_display_field(BRIDGE_PATH_U64, 9, "Amount")
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_bridge_token_amount_native(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_TOKEN_AMOUNT with is_native=1: displays as 'X SOL'."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 1_000_000_000))
    _begin_session(sol, message)

    display_field = _build_token_amount_display_field(BRIDGE_PATH_U64, True, "Amount")
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_bridge_token_amount_unknown(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_TOKEN_AMOUNT with no mint reference (MINT_NONE): the amount is a
    plain number with no ticker, so it renders bare as 'X'."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 1_000_000))
    _begin_session(sol, message)

    display_field = _build_token_amount_display_field(BRIDGE_PATH_U64, False, "Amount")
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


# ── TOKEN_AMOUNT mint resolution (TOKEN_ACCOUNT_STATE consumption) ────────────

def test_token_amount_resolved_via_token_account_state(backend, sol, scenario_navigator,
                                                        root_pytest_dir):
    """A TOKEN_AMOUNT whose TOKEN is an ACCOUNT_PATH pointing at an SPL token
    account. The mint is not an in-transaction account, so it is resolved from
    the TOKEN_ACCOUNT_STATE cache, then formatted with the dynamic token's
    ticker/decimals: '1.5 GORK'."""
    token_account = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
    message = _craft_instruction_with_accounts(
        sol,
        BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(1000, 1_500_000),
        extra_accounts=[token_account],
    )
    _begin_session(sol, message)

    sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=False,
                              mint_address=SOL.GORK_MINT_ADDRESS)

    challenge = sol.get_challenge()
    sol.provide_token_account_state(
        challenge=challenge,
        account_address=token_account,
        mint=SOL.GORK_MINT_PUBLIC_KEY,
        owner=b'\x33' * 32,
        pre_balance=10_000_000,
    )

    display_field = _build_token_amount_field_with_token(
        BRIDGE_PATH_U64, "Amount",
        token_source=VALUE_SOURCE_ACCOUNT_PATH, token_payload=bytes([1]))
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_token_amount_constant_mint(backend, sol, scenario_navigator, root_pytest_dir):
    """A TOKEN_AMOUNT whose TOKEN is a CONSTANT 32-byte mint. No TOKEN_ACCOUNT_STATE
    is needed: the reference is itself the mint and resolves directly to the
    dynamic token's ticker/decimals."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 2_000_000))
    _begin_session(sol, message)

    sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=False,
                              mint_address=SOL.GORK_MINT_ADDRESS)

    display_field = _build_token_amount_field_with_token(
        BRIDGE_PATH_U64, "Amount",
        token_source=VALUE_SOURCE_CONSTANT, token_payload=SOL.GORK_MINT_PUBLIC_KEY)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_token_amount_decimals_override(backend, sol, scenario_navigator, root_pytest_dir):
    """A DECIMALS override replaces the dynamic token's magnitude (6) with 2, so
    a raw value of 150 renders as '1.5 GORK' instead of '0.00015 GORK'."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 150))
    _begin_session(sol, message)

    sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=False,
                              mint_address=SOL.GORK_MINT_ADDRESS)

    display_field = _build_token_amount_field_with_token(
        BRIDGE_PATH_U64, "Amount",
        token_source=VALUE_SOURCE_CONSTANT, token_payload=SOL.GORK_MINT_PUBLIC_KEY,
        decimals=2)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_token_amount_mint_assoc_priority_over_tas(backend, sol, scenario_navigator,
                                                   root_pytest_dir):
    """When both a MINT_ASSOC binding and a TOKEN_ACCOUNT_STATE entry map the same
    token account, the MINT_ASSOC binding wins. The TAS deliberately maps the
    account to USDC; the MINT_ASSOC binds it to the GORK mint, so 'GORK' is shown."""
    token_account = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
    mint_account = SOL.GORK_MINT_PUBLIC_KEY
    message = _craft_instruction_with_accounts(
        sol,
        BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(1000, 1_500_000),
        extra_accounts=[token_account, mint_account],
    )
    _begin_session(sol, message)

    sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=False,
                              mint_address=SOL.GORK_MINT_ADDRESS)

    challenge = sol.get_challenge()
    sol.provide_token_account_state(
        challenge=challenge,
        account_address=token_account,
        mint=SOL.USDC_MINT_PUBLIC_KEY,  # deliberately different; must be ignored
        owner=b'\x33' * 32,
        pre_balance=0,
    )

    display_field = _build_token_amount_field_with_token(
        BRIDGE_PATH_U64, "Amount",
        token_source=VALUE_SOURCE_ACCOUNT_PATH, token_payload=bytes([1]))
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
        mint_assoc_account=1,
        mint_assoc_mint=2,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_token_amount_argument_path_token_rejected(backend):
    """A TOKEN reference sourced from ARGUMENT_PATH is not supported and must be
    refused at ingest, when the substructure is provided (fail closed)."""
    sol = SolanaClient(backend)
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 1_500_000))
    _begin_session(sol, message)

    display_field = _build_token_amount_field_with_token(
        BRIDGE_PATH_U64, "Amount",
        token_source=VALUE_SOURCE_ARGUMENT_PATH, token_payload=BRIDGE_PATH_DISC)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE


def test_bridge_account_param_type(backend, sol, scenario_navigator, root_pytest_dir):
    """ACCOUNT_PATH source: displays as base58 short form (7..7)."""
    destination_pubkey = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
    message = _craft_instruction_with_accounts(
        sol,
        BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(42, 7_000_000),
        extra_accounts=[destination_pubkey],
    )
    _begin_session(sol, message)

    display_field = _build_account_display_field(1, "Destination")
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


# ── ENUM end-to-end: variant name resolution and payload consumption ─────────

# Synthetic program whose single instruction argument struct starts with a
# 1-byte discriminator (BYTES_FIXED) followed by an ENUM field "sw" with 3
# variants (indices 0,1,2). The enum discriminator is a single u8 read from
# the instruction data.
ENUM_PROGRAM_ID = b'\x0e' * 32
ENUM_DISCRIMINATOR = b'\x0e'
ENUM_ID = "sw"

# Path steps: STRUCT steps are 1 byte (the child index).
#   ENUM_PATH → root STRUCT child 1 (the enum field itself)
ENUM_PATH = b'\x01\x01'


def _enum_pool_empty() -> bytes:
    """IDL pool: STRUCT{ BYTES_FIXED(1) disc, ENUM sw }."""
    return bytes([
        3,
        0x20, 0x02, 0x01, 0x02,          # [0] STRUCT field_count=2 refs=[1,2]
        0x12, 0x00, 0x01,                # [1] BYTES_FIXED fixed_size=1 (discriminator)
        0x28, 0x01, 0x00, 0x03, 0x02,    # [2] ENUM disc=U8 total_variants=3 id_len=2
        ord('s'), ord('w'),
    ])


def test_enum_empty_variant_displays_name(backend, sol, scenario_navigator, root_pytest_dir):
    """EMPTY payload: the walker resolves the enum leaf to its variant name and
    the renderer displays it (no payload bytes consumed)."""
    # data: discriminator byte, then enum discriminator = variant index 1.
    data = ENUM_DISCRIMINATOR + bytes([1])
    message = _craft_single_instruction_message(sol, ENUM_PROGRAM_ID, data)
    _begin_session(sol, message)

    display_field = _build_enum_display_field(ENUM_PATH, "Route")
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=ENUM_PROGRAM_ID,
        discriminator=ENUM_DISCRIMINATOR,
        operation_type="Swap",
        program_name="SwapDex",
        substructures_hash=substructures_hash,
        idl_type_pool=_enum_pool_empty(),
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    sol.provide_enum_variant(
        program_id=ENUM_PROGRAM_ID,
        enum_id=ENUM_ID,
        variant_index=1,
        variant_name="Orca",
        payload_kind=0x00,  # EMPTY
    )

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_enum_missing_variant_refused(backend, sol):
    """No matching variant registered: the walker cannot resolve the enum leaf,
    so FINALIZE must fail closed."""
    data = ENUM_DISCRIMINATOR + bytes([1])
    message = _craft_single_instruction_message(sol, ENUM_PROGRAM_ID, data)
    _begin_session(sol, message)

    display_field = _build_enum_display_field(ENUM_PATH, "Route")
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=ENUM_PROGRAM_ID,
        discriminator=ENUM_DISCRIMINATOR,
        operation_type="Swap",
        program_name="SwapDex",
        substructures_hash=substructures_hash,
        idl_type_pool=_enum_pool_empty(),
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    # Deliberately do NOT provide the enum variant.

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.INVALID_GENERIC_PREVIEW


def test_enum_raw_size_variant_skips_payload(backend, sol, scenario_navigator, root_pytest_dir):
    """RAW_SIZE payload: the walker skips the fixed number of opaque payload
    bytes, so a trailing field after the enum decodes correctly."""
    #   [0] STRUCT field_count=3 refs=[1,2,3]
    #   [1] BYTES_FIXED(1) discriminator
    #   [2] ENUM sw
    #   [3] U8 trailing
    pool = bytes([
        4,
        0x20, 0x03, 0x01, 0x02, 0x03,
        0x12, 0x00, 0x01,
        0x28, 0x01, 0x00, 0x03, 0x02, ord('s'), ord('w'),
        0x01,
    ])
    tail_path = b'\x01\x02'

    # data: disc, variant index 2, 2 opaque payload bytes, trailing u8 = 0x7F.
    data = ENUM_DISCRIMINATOR + bytes([2]) + b'\xAA\xBB' + bytes([0x7F])
    message = _craft_single_instruction_message(sol, ENUM_PROGRAM_ID, data)
    _begin_session(sol, message)

    enum_field = _build_enum_display_field(ENUM_PATH, "Route")
    tail_field = _build_display_field_named(tail_path, "Tail")
    substructures_hash = hashlib.sha256(enum_field + tail_field).digest()

    sol.provide_instruction_info(
        program_id=ENUM_PROGRAM_ID,
        discriminator=ENUM_DISCRIMINATOR,
        operation_type="Swap",
        program_name="SwapDex",
        substructures_hash=substructures_hash,
        idl_type_pool=pool,
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, enum_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, tail_field)
    sol.provide_enum_variant(
        program_id=ENUM_PROGRAM_ID,
        enum_id=ENUM_ID,
        variant_index=2,
        variant_name="Jupiter",
        payload_kind=0x03,  # RAW_SIZE
        variant_payload=b'\x00\x02',  # 2 opaque bytes
    )

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_enum_inline_variant_inner_field(backend, sol, scenario_navigator, root_pytest_dir):
    """INLINE payload: the variant carries a self-contained inline type
    descriptor whose inner fields become addressable leaves."""
    # Inline descriptor: STRUCT{ U8 } embedded in the variant.
    inline_desc = bytes([0x20, 0x01, 0x01])  # STRUCT child_count=1, child U8

    # data: disc, enum discriminator = variant index 1, inner u8 = 0x42.
    data = ENUM_DISCRIMINATOR + bytes([1]) + bytes([0x42])
    message = _craft_single_instruction_message(sol, ENUM_PROGRAM_ID, data)
    _begin_session(sol, message)

    enum_field = _build_enum_display_field(ENUM_PATH, "Route")
    # Path into the inline payload: root STRUCT child 1 (enum),
    # variant index 1, inline STRUCT child 0.
    inner_path = bytes([3, 1, 1, 0])
    inner_field = _build_display_field_named(inner_path, "Inner")
    substructures_hash = hashlib.sha256(enum_field + inner_field).digest()

    sol.provide_instruction_info(
        program_id=ENUM_PROGRAM_ID,
        discriminator=ENUM_DISCRIMINATOR,
        operation_type="Swap",
        program_name="SwapDex",
        substructures_hash=substructures_hash,
        idl_type_pool=_enum_pool_empty(),
        idl_root_type=0,
    )

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, enum_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, inner_field)
    sol.provide_enum_variant(
        program_id=ENUM_PROGRAM_ID,
        enum_id=ENUM_ID,
        variant_index=1,
        variant_name="Orca",
        payload_kind=0x02,  # INLINE
        variant_payload=inline_desc,
    )

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)

    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_enum_skip_inner_true_accepted(backend, sol):
    """SKIP_INNER=1 on a PARAM_ENUM is accepted: the walker still consumes the
    INLINE payload bytes and, with no inner display field, only the variant name
    is displayable. The session finalizes."""
    inline_desc = bytes([0x20, 0x01, 0x01])  # STRUCT{ U8 }
    data = ENUM_DISCRIMINATOR + bytes([1]) + bytes([0x42])
    message = _craft_single_instruction_message(sol, ENUM_PROGRAM_ID, data)
    _begin_session(sol, message)

    enum_field = _build_enum_display_field(ENUM_PATH, "Route", skip_inner=b'\x01')
    substructures_hash = hashlib.sha256(enum_field).digest()

    sol.provide_instruction_info(
        program_id=ENUM_PROGRAM_ID,
        discriminator=ENUM_DISCRIMINATOR,
        operation_type="Swap",
        program_name="SwapDex",
        substructures_hash=substructures_hash,
        idl_type_pool=_enum_pool_empty(),
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, enum_field)
    sol.provide_enum_variant(
        program_id=ENUM_PROGRAM_ID,
        enum_id=ENUM_ID,
        variant_index=1,
        variant_name="Orca",
        payload_kind=0x02,  # INLINE
        variant_payload=inline_desc,
    )

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


def test_enum_skip_inner_false_accepted(backend, sol):
    """SKIP_INNER=0 (explicit) on a PARAM_ENUM is accepted and finalizes."""
    data = ENUM_DISCRIMINATOR + bytes([1])
    message = _craft_single_instruction_message(sol, ENUM_PROGRAM_ID, data)
    _begin_session(sol, message)

    enum_field = _build_enum_display_field(ENUM_PATH, "Route", skip_inner=b'\x00')
    substructures_hash = hashlib.sha256(enum_field).digest()

    sol.provide_instruction_info(
        program_id=ENUM_PROGRAM_ID,
        discriminator=ENUM_DISCRIMINATOR,
        operation_type="Swap",
        program_name="SwapDex",
        substructures_hash=substructures_hash,
        idl_type_pool=_enum_pool_empty(),
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, enum_field)
    sol.provide_enum_variant(
        program_id=ENUM_PROGRAM_ID,
        enum_id=ENUM_ID,
        variant_index=1,
        variant_name="Orca",
        payload_kind=0x00,  # EMPTY
    )

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000
    _wipe_session(sol)


def test_enum_skip_inner_invalid_value_rejected(backend, sol):
    """A PARAM_ENUM SKIP_INNER byte outside {0, 1} is refused at ingest."""
    data = ENUM_DISCRIMINATOR + bytes([1])
    message = _craft_single_instruction_message(sol, ENUM_PROGRAM_ID, data)
    _begin_session(sol, message)

    enum_field = _build_enum_display_field(ENUM_PATH, "Route", skip_inner=b'\x02')
    sol.provide_instruction_info(
        program_id=ENUM_PROGRAM_ID,
        discriminator=ENUM_DISCRIMINATOR,
        operation_type="Swap",
        program_name="SwapDex",
        substructures_hash=hashlib.sha256(enum_field).digest(),
        idl_type_pool=_enum_pool_empty(),
        idl_root_type=0,
    )
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, enum_field)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE


def test_enum_skip_inner_invalid_size_rejected(backend, sol):
    """A multi-byte PARAM_ENUM SKIP_INNER is refused at ingest."""
    data = ENUM_DISCRIMINATOR + bytes([1])
    message = _craft_single_instruction_message(sol, ENUM_PROGRAM_ID, data)
    _begin_session(sol, message)

    enum_field = _build_enum_display_field(ENUM_PATH, "Route", skip_inner=b'\x00\x00')
    sol.provide_instruction_info(
        program_id=ENUM_PROGRAM_ID,
        discriminator=ENUM_DISCRIMINATOR,
        operation_type="Swap",
        program_name="SwapDex",
        substructures_hash=hashlib.sha256(enum_field).digest(),
        idl_type_pool=_enum_pool_empty(),
        idl_root_type=0,
    )
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, enum_field)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE


# ─── End-to-end: clear signing + delayed signing ─────────────────────────────

def _craft_message_with_blockhash(sol: SolanaClient, program_id: bytes,
                                  data: bytes, blockhash: bytes,
                                  sender_pubkey: bytes) -> bytes:
    """Build a single-instruction message with a specific blockhash."""
    sender = Pubkey.from_bytes(sender_pubkey)
    instruction = Instruction(
        program_id=Pubkey.from_bytes(program_id),
        accounts=[AccountMeta(pubkey=sender, is_signer=True, is_writable=True)],
        data=data,
    )
    return sol.craft_tx([instruction], sender, blockhash=Hash.from_bytes(blockhash))


def test_clear_signing_delayed_sign_valid(backend, sol, navigator,
                                          scenario_navigator, root_pytest_dir):
    """Full end-to-end: generic preview → descriptors → finalize → UI approve →
    delayed sign. Verifies the Ed25519 signature over the final message."""

    from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

    # Build message with ZEROED blockhash (for preview fingerprint)
    preview_message = _craft_message_with_blockhash(
        sol, BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(1000, 5_000_000),
        blockhash=bytes(32),
        sender_pubkey=from_public_key,
    )

    # Phase 0: Open clear-signing session (INS 0x0A)
    _begin_session(sol, preview_message)

    # Phase B: Provide instruction template
    display_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    # Finalize (INS 0x0C) — validates descriptors
    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    # Prompt UI (INS 0x0B) — user approves, fingerprint armed
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000

    # Delayed sign (INS 0x09) — same message but with REAL blockhash
    real_blockhash = bytes([0xAB] * 32)
    final_message = _craft_message_with_blockhash(
        sol, BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(1000, 5_000_000),
        blockhash=real_blockhash,
        sender_pubkey=from_public_key,
    )

    signature = sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_message).data
    assert len(signature) == 64
    verify_signature(from_public_key, final_message, signature)

    # Dismiss the "Transaction signed" status screen shown by delayed sign
    if backend.device.is_nano:
        dismiss_instructions = [NavInsID.BOTH_CLICK]
    else:
        dismiss_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
    navigator.navigate_and_compare(
        path=root_pytest_dir,
        instructions=dismiss_instructions,
        test_case_name="delayed_sign_status",
        screen_change_before_first_instruction=False,
    )


def test_clear_signing_delayed_sign_rejected(backend, sol, navigator,
                                             scenario_navigator, root_pytest_dir):
    """Clear signing review rejected → delayed sign fails with no-preview error."""

    from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

    # Build message with zeroed blockhash
    preview_message = _craft_message_with_blockhash(
        sol, BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(1000, 5_000_000),
        blockhash=bytes(32),
        sender_pubkey=from_public_key,
    )

    _begin_session(sol, preview_message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    substructures_hash = hashlib.sha256(display_field).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    rapdu = sol.finalize_generic_clear_signing()
    assert rapdu.status == 0x9000

    # User REJECTS the review → fingerprint discarded
    with pytest.raises(ExceptionRAPDU) as exc_info:
        with sol.send_prompt_ui_display():
            scenario_navigator.review_reject(path=root_pytest_dir)
    assert exc_info.value.status == ErrorType.USER_CANCEL

    # Delayed sign should fail — no armed fingerprint
    real_blockhash = bytes([0xAB] * 32)
    final_message = _craft_message_with_blockhash(
        sol, BRIDGE_PROGRAM_ID,
        _bridge_instruction_data(1000, 5_000_000),
        blockhash=real_blockhash,
        sender_pubkey=from_public_key,
    )

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_message)
    assert exc_info.value.status == ErrorType.SOLANA_DELAYED_PREVIEW_NOT_FOUND


# ── CS SESSION STATE MACHINE ─────────────────────────────────────────────────

# Helper: craft a valid message suitable for opening a CS session.
def _dummy_cs_message(sol: SolanaClient) -> bytes:
    program_id = b'\x01' * 32
    data = b'\xDE\xAD' + b'\x00' * 4
    return _craft_single_instruction_message(sol, program_id, data)


# APDUs that require STREAMING but are sent from IDLE (no session opened).
@pytest.mark.parametrize("apdu_name, send_fn", [
    ("INSTRUCTION_INFO", lambda sol: sol._client.exchange(
        CLA, INS.INS_INSTRUCTION_INFO, P1_NON_CONFIRM, P2_NONE, b"\x00")),
    ("INSTRUCTION_SUBSTRUCTURE", lambda sol: sol._client.exchange(
        CLA, INS.INS_INSTRUCTION_SUBSTRUCTURE, P1_NON_CONFIRM, P2_NONE, b"\x00")),
    ("FINALIZE", lambda sol: sol.finalize_generic_clear_signing()),
])
def test_cs_streaming_apdu_rejected_from_idle(backend, apdu_name, send_fn):
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        send_fn(sol)
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


# PROMPT_UI_DISPLAY requires FINALIZED but is sent from IDLE.
def test_cs_prompt_rejected_from_idle(backend):
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.prompt_ui_display()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


# PROMPT_UI_DISPLAY sent from STREAMING (session opened, not finalized).
def test_cs_prompt_rejected_from_streaming(backend):
    sol = SolanaClient(backend)
    message = _dummy_cs_message(sol)
    _begin_session(sol, message)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.prompt_ui_display()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


# START SESSION sent twice — second one should fail (state is STREAMING, not IDLE).
def test_cs_double_start_session_rejected(backend):
    sol = SolanaClient(backend)
    message = _dummy_cs_message(sol)
    _begin_session(sol, message)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        _begin_session(sol, message)
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


# FINALIZE sent from FINALIZED (double finalize after a session was finalized).
# Reaching FINALIZED requires a fully valid session, so we use IDLE instead —
# state was reset by the first failing FINALIZE attempt.
# Instead, test that FINALIZE from IDLE is rejected (covered above).

# APDUs that require STREAMING sent from FINALIZED — not easily testable without
# a full end-to-end session. Test that a non-CS APDU resets the session instead.

# A rejected garbage APDU wipes a STREAMING session (any error abandons the session).
def test_cs_false_apdu_resets_streaming_session(backend):
    sol = SolanaClient(backend)
    _begin_session(sol, _dummy_cs_message(sol))
    _wipe_session(sol)
    # Session is gone: FINALIZE now fails as if none were open.
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INVALID_STATE


# Stateless APDUs do NOT reset a STREAMING session. They answer from the seed or from
# settings and touch no signing state, so a host is free to interleave them while it
# streams descriptors.
@pytest.mark.parametrize("stateless_fn", [
    lambda sol: sol.get_challenge(),
    lambda sol: sol.get_app_configuration(),
    lambda sol: sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH),
])
def test_cs_stateless_apdu_preserves_streaming_session(backend, stateless_fn):
    sol = SolanaClient(backend)
    message = _dummy_cs_message(sol)
    _begin_session(sol, message)
    # Send a stateless APDU — should succeed without resetting the session
    stateless_fn(sol)
    # FINALIZE should still be reachable (state is still STREAMING)
    # It will fail for content reasons (no templates), not for state reasons
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INCOMPLETE


# ── TYPED PARAM formatting: DATETIME / DURATION / UNIT / ACCOUNT / STRING ─────

# A synthetic program whose argument struct is
#   {pubkey, u64, u32, string(u8-prefixed utf8)}
# preceded by a 1-byte discriminator consumed by a BYTES_FIXED root field.
TYPED_PROGRAM_ID = b'\x09' * 32
TYPED_DISCRIMINATOR = b'\x09'

# IDL type pool: u8 count || entries.
#   [0] STRUCT(0x20) field_count=5 refs=[1,2,3,4,5]
#   [1] BYTES_FIXED(0x12) fixed_size=1   (consumes the discriminator)
#   [2] PUBKEY_32(0x11)
#   [3] U64(0x04)
#   [4] U32(0x03)
#   [5] STRING_PREFIXED(0x14) prefix_kind=U8 encoding=UTF8
TYPED_POOL = bytes([6,
                    0x20, 5, 1, 2, 3, 4, 5,
                    0x12, 0x00, 0x01,
                    0x11,
                    0x04,
                    0x03,
                    0x14, 0x01, 0x00])

# Packed argument paths (u8 step_count || packed steps); STRUCT steps are 1 byte.
TYPED_PATH_PUBKEY = b'\x01\x01'
TYPED_PATH_U64 = b'\x01\x02'
TYPED_PATH_U32 = b'\x01\x03'
TYPED_PATH_STRING = b'\x01\x04'


def _typed_instruction_data(pubkey: bytes, u64_value: int, u32_value: int, text: bytes) -> bytes:
    return (TYPED_DISCRIMINATOR
            + pubkey
            + struct.pack("<Q", u64_value)
            + struct.pack("<I", u32_value)
            + bytes([len(text)]) + text)


def _provide_typed_info(sol: SolanaClient, substructures_hash: bytes) -> None:
    sol.provide_instruction_info(
        program_id=TYPED_PROGRAM_ID,
        discriminator=TYPED_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Typed",
        substructures_hash=substructures_hash,
        idl_type_pool=TYPED_POOL,
        idl_root_type=0,
    )


def test_typed_datetime(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_DATETIME with default ticks: a u64 of Unix seconds renders as a date."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 1_700_000_000, 0, b"x"))
    _begin_session(sol, message)

    display_field = _build_datetime_display_field(TYPED_PATH_U64, "When")
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_datetime_millisecond_ticks(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_DATETIME with ticks_per_second=1000 scales milliseconds to seconds."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 1_700_000_000_000, 0, b"x"))
    _begin_session(sol, message)

    display_field = _build_datetime_display_field(TYPED_PATH_U64, "When", ticks_per_second=1000)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_datetime_signed_i64(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_DATETIME over a signed i64 leaf. Solana's UnixTimestamp is i64, so a
    DATETIME field pointing at a signed leaf must render, not be refused."""
    program_id = b'\x0a' * 32
    discriminator = b'\x0a'
    # Pool: STRUCT(2 fields) = [BYTES_FIXED(disc), I64].
    pool = bytes([3, 0x20, 2, 1, 2, 0x12, 0x00, 0x01, IDL_KIND_I64])
    path_i64 = b'\x01\x01'

    message = _craft_single_instruction_message(
        sol, program_id, discriminator + struct.pack("<q", 1_700_000_000))
    _begin_session(sol, message)

    display_field = _build_datetime_display_field(path_i64, "When")
    sol.provide_instruction_info(
        program_id=program_id,
        discriminator=discriminator,
        operation_type="Transfer",
        program_name="Typed",
        substructures_hash=hashlib.sha256(display_field).digest(),
        idl_type_pool=pool,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_duration(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_DURATION: a u32 of seconds renders as H:MM:SS (3661 -> 1:01:01)."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 3661, b"x"))
    _begin_session(sol, message)

    display_field = _build_duration_display_field(TYPED_PATH_U32, "Lockup")
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_unit_suffix(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_UNIT with a suffix symbol: 1250 scaled by 2 decimals -> '12.5%'."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 1250, b"x"))
    _begin_session(sol, message)

    display_field = _build_unit_display_field(TYPED_PATH_U32, "Rate", symbol="%", decimals=2)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_account_short_form(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_ACCOUNT: a 32-byte argument leaf renders as a base58 short address."""
    pubkey = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(pubkey, 0, 0, b"x"))
    _begin_session(sol, message)

    display_field = _build_account_argument_display_field(TYPED_PATH_PUBKEY, "Owner")
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_string_ascii(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_STRING with ASCII encoding renders the leaf bytes verbatim.

    The value is 89 characters, past the old 65-char display cap, so it also
    covers rendering a value longer than the previous fixed buffer.
    """
    memo = b"This memo is deliberately longer than sixty-five characters to exercise the display path."
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 0, memo))
    _begin_session(sol, message)

    display_field = _build_string_display_field(TYPED_PATH_STRING, "Memo",
                                                encoding=STRING_ENCODING_ASCII)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_string_hex(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_STRING with HEX encoding renders the leaf bytes as lowercase hex."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 0, b"\xde\xad\xbe\xef"))
    _begin_session(sol, message)

    display_field = _build_string_display_field(TYPED_PATH_STRING, "Data",
                                                encoding=STRING_ENCODING_HEX)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_string_slice_source_bounded(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_STRING slicing the source bytes [1,4) before ASCII encoding -> 'bcd'."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 0, b"abcdef"))
    _begin_session(sol, message)

    display_field = _build_string_display_field(
        TYPED_PATH_STRING, "Slice",
        encoding=STRING_ENCODING_ASCII,
        slice_kind=SLICE_KIND_BOUNDED, slice_start=1, slice_end=4,
        slice_applies_to=SLICE_APPLIES_TO_SOURCE)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


# ── TYPED PARAM ingest error paths (rejected before any UI) ──────────────────

def test_typed_datetime_zero_ticks_rejected(backend, sol):
    """A PARAM_DATETIME with TICKS_PER_SECOND=0 is refused at ingest."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 1_700_000_000, 0, b"x"))
    _begin_session(sol, message)

    display_field = _build_datetime_display_field(TYPED_PATH_U64, "When", ticks_per_second=0)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE


def test_typed_string_unknown_encoding_rejected(backend, sol):
    """A PARAM_STRING with an unrecognized encoding is refused at ingest."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 0, b"hi"))
    _begin_session(sol, message)

    display_field = _build_string_display_field(TYPED_PATH_STRING, "Memo", encoding=0x7F)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE


def test_typed_string_bounded_with_size_rejected(backend, sol):
    """A BOUNDED slice carrying a SLICE_SIZE tag is contradictory and refused."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 0, b"abcdef"))
    _begin_session(sol, message)

    display_field = _build_string_display_field(
        TYPED_PATH_STRING, "Slice",
        encoding=STRING_ENCODING_ASCII,
        slice_kind=SLICE_KIND_BOUNDED, slice_start=1, slice_size=3)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE


def test_typed_string_base64(backend, sol, scenario_navigator, root_pytest_dir):
    """PARAM_STRING with BASE64 encoding renders the leaf bytes as base64."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 0, b"\x01\x02\x03"))
    _begin_session(sol, message)

    display_field = _build_string_display_field(TYPED_PATH_STRING, "Data",
                                                encoding=STRING_ENCODING_BASE64)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_typed_string_slice_formatted_sized_reversed(backend, sol, scenario_navigator,
                                                     root_pytest_dir):
    """PARAM_STRING taking the trailing 3 units of the ASCII-formatted string
    (SIZED + REVERSED, applied to the formatted output) -> 'def' from 'abcdef'."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 0, 0, b"abcdef"))
    _begin_session(sol, message)

    display_field = _build_string_display_field(
        TYPED_PATH_STRING, "Tail",
        encoding=STRING_ENCODING_ASCII,
        slice_kind=SLICE_KIND_SIZED, slice_size=3, slice_reversed=True,
        slice_applies_to=SLICE_APPLIES_TO_FORMATTED)
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


# ── TRUSTED_NAME end-to-end (PARAM_TRUSTED_NAME + INS 0x29) ───────────────────

def test_trusted_name_resolves_and_displays(backend, sol, scenario_navigator, root_pytest_dir):
    """A PARAM_TRUSTED_NAME field over a 32-byte pubkey argument resolves to the
    name carried by a TRUSTED_NAME descriptor (INS 0x29) and displays it."""
    named_address = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(named_address, 0, 0, b"x"))
    _begin_session(sol, message)

    # Phase A: the CAL-signed trusted name for the address (no challenge needed).
    sol.provide_cs_trusted_name(address=named_address, name="MyToken",
                                name_type=TRUSTED_NAME_TYPE_TOKEN)

    display_field = _build_trusted_name_display_field(
        TYPED_PATH_PUBKEY, "Token", allowed_types=[TRUSTED_NAME_TYPE_TOKEN])
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_trusted_name_type_not_allowed_shows_address(backend, sol, scenario_navigator,
                                                     root_pytest_dir):
    """When the cached name's type is outside the field's allow-list, the device
    falls back to the short base58 address rather than showing the name."""
    named_address = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(named_address, 0, 0, b"x"))
    _begin_session(sol, message)

    # The name is a TOKEN, but the field only permits SMART_CONTRACT.
    sol.provide_cs_trusted_name(address=named_address, name="MyToken",
                                name_type=TRUSTED_NAME_TYPE_TOKEN)

    display_field = _build_trusted_name_display_field(
        TYPED_PATH_PUBKEY, "Token", allowed_types=[TRUSTED_NAME_TYPE_SMART_CONTRACT])
    _provide_typed_info(sol, hashlib.sha256(display_field).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


# ── FINALIZE failure: descriptors do not match the streamed transaction ───────

def test_finalize_substructure_hash_mismatch_incomplete(backend, sol):
    """A DISPLAY_FIELD whose hash never matches the INSTRUCTION_INFO's committed
    SUBSTRUCTURES_HASH leaves the template uncommitted; finalize refuses as
    incomplete rather than signing an unauthenticated descriptor set."""
    message = _craft_single_instruction_message(
        sol, BRIDGE_PROGRAM_ID, _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=b'\x00' * 32,  # never matches the streamed substructure
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INCOMPLETE


def test_finalize_descriptor_program_mismatch_rejected(backend, sol):
    """A committed template whose PROGRAM_ID does not match the streamed
    instruction leaves the walk unable to resolve a template: finalize refuses."""
    message = _craft_single_instruction_message(
        sol, BRIDGE_PROGRAM_ID, _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    sol.provide_instruction_info(
        program_id=b'\x7e' * 32,  # not the transaction's program
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Wrong",
        substructures_hash=hashlib.sha256(display_field).digest(),
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.INVALID_GENERIC_PREVIEW


def test_finalize_descriptor_discriminator_mismatch_rejected(backend, sol):
    """A committed template for the right program but a discriminator that is not
    a prefix of the instruction data matches nothing: finalize refuses."""
    message = _craft_single_instruction_message(
        sol, BRIDGE_PROGRAM_ID, _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    display_field = _build_display_field(BRIDGE_PATH_U32)
    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=b'\xff',  # transaction data starts with 0x07, not 0xff
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=hashlib.sha256(display_field).digest(),
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.INVALID_GENERIC_PREVIEW


# ── ALT resolution end-to-end (v0 versioned transaction) ──────────────────────

# A program whose single instruction references an ALT-loaded account.
ALT_PROGRAM_ID = b'\x0c' * 32
ALT_DISCRIMINATOR = b'\x0c'
# IDL type pool: STRUCT(1 field) = [BYTES_FIXED(1)] consuming the 1-byte discriminator.
ALT_POOL = bytes([2, 0x20, 1, 1, 0x12, 0x00, 0x01])
ALT_TABLE_ADDRESS = b'\xa0' * 32
ALT_ENTRY_INDEX = 7


def _craft_v0_message_with_alt(sender_pubkey: bytes, program_id: bytes,
                               instruction_data: bytes, *,
                               instruction_account_indexes: bytes,
                               alt_table_address: bytes,
                               alt_writable_entries: list,
                               alt_readonly_entries: list) -> bytes:
    """Hand-craft a v0 (versioned) message with one ALT lookup table.

    Static keys are [sender (signer), program]. The single instruction's account
    indexes may reference ALT-loaded accounts (global index >= static key count),
    which the device resolves through the ALT section + a signed ALT_RESOLUTION
    descriptor. All compact-u16 counts stay below 128 (single byte). The layout
    mirrors libsol/parser.c parse_message_header + the ALT section."""
    static_keys = [sender_pubkey, program_id]
    body = bytes([0x80])              # version prefix: versioned, version 0
    body += bytes([1, 0, 1])         # num_required_sigs, ro_signed, ro_unsigned (program)
    body += bytes([len(static_keys)])
    for key in static_keys:
        body += key
    body += bytes(32)                # blockhash (zeroed, as for the preview fingerprint)
    body += bytes([1])               # instructions_length
    # single instruction: program is static key 1
    body += bytes([1])
    body += bytes([len(instruction_account_indexes)]) + instruction_account_indexes
    body += bytes([len(instruction_data)]) + instruction_data
    # address-table-lookup section: one table
    body += bytes([1])               # num_tables
    body += alt_table_address
    body += bytes([len(alt_writable_entries)]) + bytes(alt_writable_entries)
    body += bytes([len(alt_readonly_entries)]) + bytes(alt_readonly_entries)
    return body


def test_alt_loaded_account_resolved_and_displayed(backend, sol, scenario_navigator,
                                                   root_pytest_dir):
    """A v0 transaction references an ALT-loaded account (global index beyond the
    static keys). Finalize maps it back to (alt_address, entry_index), resolves it
    through a signed ALT_RESOLUTION descriptor, and displays the concrete address."""
    sender = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
    resolved_address = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))

    # Static keys are indexes 0..1; global index 2 is the first ALT writable entry.
    message = _craft_v0_message_with_alt(
        sender, ALT_PROGRAM_ID, ALT_DISCRIMINATOR,
        instruction_account_indexes=bytes([2]),
        alt_table_address=ALT_TABLE_ADDRESS,
        alt_writable_entries=[ALT_ENTRY_INDEX],
        alt_readonly_entries=[],
    )
    _begin_session(sol, message)

    challenge = sol.get_challenge()
    sol.provide_alt_resolution(
        challenge=challenge,
        alt_address=ALT_TABLE_ADDRESS,
        entry_index=ALT_ENTRY_INDEX,
        resolved_address=resolved_address,
    )

    display_field = _build_account_display_field(0, "Delegate")
    sol.provide_instruction_info(
        program_id=ALT_PROGRAM_ID,
        discriminator=ALT_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="AltProg",
        substructures_hash=hashlib.sha256(display_field).digest(),
        idl_type_pool=ALT_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_alt_loaded_account_without_resolution_refused(backend, sol):
    """Without a matching ALT_RESOLUTION descriptor, an ALT-loaded account cannot
    be resolved to a concrete key and finalize refuses to sign (fail closed)."""
    sender = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
    message = _craft_v0_message_with_alt(
        sender, ALT_PROGRAM_ID, ALT_DISCRIMINATOR,
        instruction_account_indexes=bytes([2]),
        alt_table_address=ALT_TABLE_ADDRESS,
        alt_writable_entries=[ALT_ENTRY_INDEX],
        alt_readonly_entries=[],
    )
    _begin_session(sol, message)

    display_field = _build_account_display_field(0, "Delegate")
    sol.provide_instruction_info(
        program_id=ALT_PROGRAM_ID,
        discriminator=ALT_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="AltProg",
        substructures_hash=hashlib.sha256(display_field).digest(),
        idl_type_pool=ALT_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.INVALID_GENERIC_PREVIEW


def test_alt_truncated_section_refused(backend, sol):
    """A v0 transaction whose address-table-lookup section is cut short is refused,
    even though its only instruction references a static key and would display fine.
    That section fixes which loaded accounts are writable, and the merge guards read
    writability over every raw account, so a section the device cannot parse leaves it
    unable to reason about the transaction. Session start validates the header alone,
    so such a message reaches finalize."""
    sender = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
    message = _craft_v0_message_with_alt(
        sender, ALT_PROGRAM_ID, ALT_DISCRIMINATOR,
        instruction_account_indexes=bytes([0]),
        alt_table_address=ALT_TABLE_ADDRESS,
        alt_writable_entries=[ALT_ENTRY_INDEX],
        alt_readonly_entries=[],
    )
    # Drop the tail of the lookup section: the table's index lists no longer parse.
    _begin_session(sol, message[:-2])

    display_field = _build_account_display_field(0, "Signer")
    sol.provide_instruction_info(
        program_id=ALT_PROGRAM_ID,
        discriminator=ALT_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="AltProg",
        substructures_hash=hashlib.sha256(display_field).digest(),
        idl_type_pool=ALT_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.INVALID_GENERIC_PREVIEW


def test_cs_amount_account_path_source_rejected(backend, sol):
    """An AMOUNT_VALUE must resolve to a number. An ACCOUNT_PATH resolves to a 32-byte
    address, which is no amount, so the substructure carrying it is refused on arrival
    rather than stored as a port whose amount nothing can compare."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    amount_value = (format_tlv(AMOUNT_VALUE_TAG_KIND, AMOUNT_KIND_NUMERIC)
                    + format_tlv(AMOUNT_VALUE_TAG_VALUE,
                                 format_tlv(ValueTag.SOURCE, VALUE_SOURCE_ACCOUNT_PATH)
                                 + format_tlv(ValueTag.PAYLOAD, bytes([0]))))
    port = (format_tlv(VFP_TAG_VERSION, 1)
            + format_tlv(VFP_TAG_SUBSTRUCT_TYPE, SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT)
            + format_tlv(VFP_TAG_DIRECTION, PORT_DIRECTION_OUTPUT)
            + format_tlv(VFP_TAG_ACCOUNT_INDEX, 0)
            + format_tlv(VFP_TAG_VALUE_KIND, PORT_VALUE_KIND_NATIVE)
            + format_tlv(VFP_TAG_AMOUNT_VALUE, amount_value))
    display_field = _build_display_field(BRIDGE_PATH_U32)

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=hashlib.sha256(display_field + port).digest(),
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, port)
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_SUBSTRUCTURE
    _wipe_session(sol)


def test_cs_amount_path_to_pubkey_leaf_refused(backend, sol):
    """A port amount whose ARGUMENT_PATH reaches a public-key leaf yields bytes no
    comparison can read. The width only becomes known once the path is resolved against
    the type pool, so this is caught at finalize rather than at ingest."""
    message = _craft_single_instruction_message(
        sol, TYPED_PROGRAM_ID,
        _typed_instruction_data(b'\x11' * 32, 5_000_000, 7, b"hi"))
    _begin_session(sol, message)

    display_field = _build_display_field(TYPED_PATH_U32)
    port = _build_value_flow_port(account_index=0, amount_path=TYPED_PATH_PUBKEY)
    _provide_typed_info(sol, hashlib.sha256(display_field + port).digest())
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, port)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.INVALID_GENERIC_PREVIEW
    _wipe_session(sol)


def test_cs_two_fields_same_argument_path(backend, sol, scenario_navigator, root_pytest_dir):
    """Two display fields may read the same argument, each with its own label. Both
    slots receive the leaf, so both render."""
    message = _craft_single_instruction_message(sol,
                                                BRIDGE_PROGRAM_ID,
                                                _bridge_instruction_data(1000, 5_000_000))
    _begin_session(sol, message)

    first = _build_display_field_named(BRIDGE_PATH_U32, "Count")
    second = _build_display_field_named(BRIDGE_PATH_U32, "Same count")
    substructures_hash = hashlib.sha256(first + second).digest()

    sol.provide_instruction_info(
        program_id=BRIDGE_PROGRAM_ID,
        discriminator=BRIDGE_DISCRIMINATOR,
        operation_type="Transfer",
        program_name="Bridge",
        substructures_hash=substructures_hash,
        idl_type_pool=BRIDGE_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, first)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, second)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


# accountEffectsDisplayedElsewhere hides an instruction only when a non-hidden survivor
# re-displays every effect it has on the target account. Two instructions each carry an input
# port on the same target: they share no output, so no junction forms and neither merges. The
# first names the hide condition on the target; the second re-displays the same amount, so the
# first is hidden when the amounts match and shown when they diverge.
COVER_HIDDEN_PROGRAM_ID = b'\x41' * 32
COVER_HIDDEN_DISCRIMINATOR = b'\x41'
COVER_SURVIVOR_PROGRAM_ID = b'\x42' * 32
COVER_SURVIVOR_DISCRIMINATOR = b'\x42'
COVER_TARGET = bytes(Pubkey.from_string("BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz"))
COVER_AMOUNT = 5_000_000
COVER_SLOT_SIGNER = 0
COVER_SLOT_TARGET = 1


def _craft_cover_message(sol: SolanaClient, *, survivor_amount: int) -> bytes:
    """Two instructions sharing the signer and the target slot; the survivor's data carries the
    amount it re-displays for the target."""
    sender = Pubkey.from_bytes(sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH))
    signer_meta = AccountMeta(pubkey=sender, is_signer=True, is_writable=True)
    target_meta = AccountMeta(pubkey=Pubkey.from_bytes(COVER_TARGET),
                              is_signer=False, is_writable=True)
    hidden = Instruction(
        program_id=Pubkey.from_bytes(COVER_HIDDEN_PROGRAM_ID),
        accounts=[signer_meta, target_meta],
        data=COVER_HIDDEN_DISCRIMINATOR + struct.pack("<Q", COVER_AMOUNT),
    )
    survivor = Instruction(
        program_id=Pubkey.from_bytes(COVER_SURVIVOR_PROGRAM_ID),
        accounts=[signer_meta, target_meta],
        data=COVER_SURVIVOR_DISCRIMINATOR + struct.pack("<Q", survivor_amount),
    )
    return sol.craft_tx([hidden, survivor], sender)


def _provide_cover_hidden(sol: SolanaClient) -> None:
    """The instruction to hide: an input port on the target and an accountEffectsDisplayedElse-
    where rule aimed at it."""
    account_field = _build_account_display_field(COVER_SLOT_TARGET, "Account")
    port = _build_value_flow_port(account_index=COVER_SLOT_TARGET,
                                  amount_path=CHAIN_TRANSFER_PATH_AMOUNT,
                                  direction=PORT_DIRECTION_INPUT)
    hide_rule = _build_hide_rule(
        target_account_index=COVER_SLOT_TARGET,
        condition=HIDE_CONDITION_ACCOUNT_EFFECTS_DISPLAYED_ELSEWHERE)
    substructures = account_field + port + hide_rule

    sol.provide_instruction_info(
        program_id=COVER_HIDDEN_PROGRAM_ID,
        discriminator=COVER_HIDDEN_DISCRIMINATOR,
        operation_type="Setup",
        program_name="Cover",
        substructures_hash=hashlib.sha256(substructures).digest(),
        idl_type_pool=CHAIN_TRANSFER_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, account_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, port)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_HIDE_RULE, hide_rule)


def _provide_cover_survivor(sol: SolanaClient) -> None:
    """The survivor: an input port on the target plus the amount and account fields that
    re-display the target's effect."""
    account_field = _build_account_display_field(COVER_SLOT_TARGET, "Account")
    amount_field = _build_amount_display_field(CHAIN_TRANSFER_PATH_AMOUNT, 9, "Amount")
    port = _build_value_flow_port(account_index=COVER_SLOT_TARGET,
                                  amount_path=CHAIN_TRANSFER_PATH_AMOUNT,
                                  direction=PORT_DIRECTION_INPUT)
    substructures = account_field + amount_field + port

    sol.provide_instruction_info(
        program_id=COVER_SURVIVOR_PROGRAM_ID,
        discriminator=COVER_SURVIVOR_DISCRIMINATOR,
        operation_type="Send",
        program_name="Cover",
        substructures_hash=hashlib.sha256(substructures).digest(),
        idl_type_pool=CHAIN_TRANSFER_POOL,
        idl_root_type=0,
    )
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, account_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, amount_field)
    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT, port)


def test_cs_account_effects_hides_covered_instruction(backend, sol, scenario_navigator,
                                                      root_pytest_dir):
    """The survivor re-displays the target's amount, so the first instruction's effects are
    displayed elsewhere and it is hidden: only the survivor is reviewed."""
    _begin_session(sol, _craft_cover_message(sol, survivor_amount=COVER_AMOUNT))
    _provide_cover_hidden(sol)
    _provide_cover_survivor(sol)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)


def test_cs_account_effects_uncovered_shows_both(backend, sol, scenario_navigator,
                                                 root_pytest_dir):
    """The survivor shows a different amount, so the first instruction's value-flow effect is
    not re-displayed and it stays visible: both instructions are reviewed."""
    _begin_session(sol, _craft_cover_message(sol, survivor_amount=COVER_AMOUNT + 1_000_000))
    _provide_cover_hidden(sol)
    _provide_cover_survivor(sol)

    assert sol.finalize_generic_clear_signing().status == 0x9000
    with sol.send_prompt_ui_display():
        scenario_navigator.review_approve(path=root_pytest_dir)
    assert sol.get_async_response().status == 0x9000
    _wipe_session(sol)
