import hashlib
import struct

import pytest

from ragger.error import ExceptionRAPDU

from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta

from application_client.solana import (SolanaClient, INS, CLA, P2_NONE, P1_NON_CONFIRM, ErrorType,
                                      TokenAccountStateTag, AltResolutionTag, EnumVariantTag,
                                      InstructionInfoTag, ValueTag)
from application_client.solana_signing_partners import INSTRUCTION_DESCRIPTOR_PARTNER
from application_client.tlv import format_tlv
from application_client import solana_utils as SOL


# DISPLAY_FIELD / PARAM / VALUE source tag values (spec/device/tlv_structs.md)
DISPLAY_FIELD_TAG_VERSION = 0x00
DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE = 0x01
DISPLAY_FIELD_TAG_NAME = 0x02
DISPLAY_FIELD_TAG_PARAM_TYPE = 0x03
DISPLAY_FIELD_TAG_PARAM = 0x04
PARAM_TYPE_RAW = 0x00
PARAM_TAG_VERSION = 0x00
PARAM_TAG_VALUE = 0x01
VALUE_SOURCE_ARGUMENT_PATH = 0x00
VALUE_SOURCE_ACCOUNT_PATH = 0x01
SUBSTRUCTURE_TYPE_DISPLAY_FIELD = 0x00


def _begin_session(sol: SolanaClient, message: bytes) -> None:
    """Open a clear-signing context by sending SIGN MESSAGE GENERIC PREVIEW (0x0A)."""
    sol.sign_message_generic_preview(SOL.SOL_PACKED_DERIVATION_PATH, message)


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


# Sending a substructure without an open clear-signing session must fail closed.
def test_substructure_without_session_rejected(backend):
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD,
                                             _build_display_field(b'\x01\x00'))
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INCOMPLETE



# ── TOKEN_ACCOUNT_STATE ──────────────────────────────────────────────────────

def test_token_account_state_valid(backend):
    sol = SolanaClient(backend)
    challenge = sol.get_challenge()
    sol.provide_token_account_state(
        challenge=challenge,
        account_address=b'\x11' * 32,
        mint=b'\x22' * 32,
        owner=b'\x33' * 32,
        pre_balance=1_000_000,
    )


def test_token_account_state_bad_challenge(backend):
    sol = SolanaClient(backend)
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
    challenge = sol.get_challenge()
    # Build manually with wrong struct type (0x99 instead of 0x15)
    payload = format_tlv(TokenAccountStateTag.STRUCT_TYPE, 0x99)
    payload += format_tlv(TokenAccountStateTag.STRUCT_VERSION, 1)
    payload += format_tlv(TokenAccountStateTag.CHALLENGE, challenge)
    payload += format_tlv(TokenAccountStateTag.ACCOUNT_ADDRESS, b'\x11' * 32)
    payload += format_tlv(TokenAccountStateTag.MINT, b'\x22' * 32)
    payload += format_tlv(TokenAccountStateTag.OWNER, b'\x33' * 32)
    payload += format_tlv(TokenAccountStateTag.PRE_BALANCE, 0)
    payload += format_tlv(TokenAccountStateTag.SIGNATURE, INSTRUCTION_DESCRIPTOR_PARTNER.sign(payload))

    sol.send_pki_certificate(INSTRUCTION_DESCRIPTOR_PARTNER)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol._exchange_split(CLA, INS.INS_TOKEN_ACCOUNT_STATE, P1_NON_CONFIRM, payload)
    assert exc_info.value.status == ErrorType.INVALID_TOKEN_ACCOUNT_STATE


def test_token_account_state_wrong_version(backend):
    """Sending unsupported version should fail."""
    sol = SolanaClient(backend)
    challenge = sol.get_challenge()
    payload = format_tlv(TokenAccountStateTag.STRUCT_TYPE, 0x15)
    payload += format_tlv(TokenAccountStateTag.STRUCT_VERSION, 99)
    payload += format_tlv(TokenAccountStateTag.CHALLENGE, challenge)
    payload += format_tlv(TokenAccountStateTag.ACCOUNT_ADDRESS, b'\x11' * 32)
    payload += format_tlv(TokenAccountStateTag.MINT, b'\x22' * 32)
    payload += format_tlv(TokenAccountStateTag.OWNER, b'\x33' * 32)
    payload += format_tlv(TokenAccountStateTag.PRE_BALANCE, 0)
    payload += format_tlv(TokenAccountStateTag.SIGNATURE, INSTRUCTION_DESCRIPTOR_PARTNER.sign(payload))

    sol.send_pki_certificate(INSTRUCTION_DESCRIPTOR_PARTNER)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol._exchange_split(CLA, INS.INS_TOKEN_ACCOUNT_STATE, P1_NON_CONFIRM, payload)
    assert exc_info.value.status == ErrorType.INVALID_TOKEN_ACCOUNT_STATE


def test_token_account_state_challenge_consumed(backend):
    """After a successful TOKEN_ACCOUNT_STATE, the challenge should be rolled.
    Reusing the same challenge should fail."""
    sol = SolanaClient(backend)
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
    challenge = sol.get_challenge()
    sol.provide_alt_resolution(
        challenge=challenge,
        alt_address=b'\xaa' * 32,
        entry_index=5,
        resolved_address=b'\xbb' * 32,
    )


def test_alt_resolution_bad_challenge(backend):
    sol = SolanaClient(backend)
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


# ── ENUM_VARIANT ─────────────────────────────────────────────────────────────

def test_enum_variant_empty_payload(backend):
    sol = SolanaClient(backend)
    sol.provide_enum_variant(
        program_id=b'\x01' * 32,
        enum_id="SwapRoute",
        variant_index=0,
        variant_name="Raydium",
        payload_kind=0x00,  # EMPTY
    )


def test_enum_variant_inline_payload(backend):
    sol = SolanaClient(backend)
    sol.provide_enum_variant(
        program_id=b'\x01' * 32,
        enum_id="SwapRoute",
        variant_index=1,
        variant_name="Orca",
        payload_kind=0x02,  # INLINE
        variant_payload=b'\x05\x01\x02',
    )


def test_enum_variant_raw_size_payload(backend):
    sol = SolanaClient(backend)
    sol.provide_enum_variant(
        program_id=b'\x01' * 32,
        enum_id="SwapRoute",
        variant_index=2,
        variant_name="Jupiter",
        payload_kind=0x03,  # RAW_SIZE
        variant_payload=b'\x00\x10',  # 16 bytes
    )


def test_enum_variant_bad_payload_kind(backend):
    sol = SolanaClient(backend)
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


def test_instruction_info_mint_assoc_incomplete(backend):
    """MINT_ASSOC_ACCOUNT without MINT_ASSOC_MINT should fail."""
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
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_INFO


def test_instruction_info_owner_assoc_incomplete(backend):
    """OWNER_ASSOC_ACCOUNT without OWNER_ASSOC_OWNER should fail."""
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
    assert exc_info.value.status == ErrorType.INVALID_INSTRUCTION_INFO


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
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INCOMPLETE


def test_finalize_without_session_rejected(backend):
    """FINALIZE GENERIC CLEAR SIGNING with no open session must fail closed."""
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.finalize_generic_clear_signing()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INCOMPLETE


def test_prompt_without_finalize_rejected(backend):
    """PROMPT UI DISPLAY without prior FINALIZE must fail closed."""
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

    sol.provide_instruction_substructure(SUBSTRUCTURE_TYPE_DISPLAY_FIELD, display_field)

    # Skip FINALIZE, go straight to PROMPT — must be rejected
    with pytest.raises(ExceptionRAPDU) as exc_info:
        sol.prompt_ui_display()
    assert exc_info.value.status == ErrorType.CLEAR_SIGNING_INCOMPLETE


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
