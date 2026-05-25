import pytest

from ragger.error import ExceptionRAPDU

from application_client.solana import (SolanaClient, INS, CLA, P2_NONE, P1_NON_CONFIRM, ErrorType,
                                      TokenAccountStateTag, AltResolutionTag, EnumVariantTag,
                                      InstructionInfoTag, ValueTag)
from application_client.solana_signing_partners import INSTRUCTION_DESCRIPTOR_PARTNER
from application_client.tlv import format_tlv


# All new clear signing INS codes should reject with UNIMPLEMENTED_INSTRUCTION
# (only INSTRUCTION_SUBSTRUCTURE remains a stub)
def test_clear_signing_stub_rejects(backend):
    sol = SolanaClient(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        backend.exchange(CLA, ins=INS.INS_INSTRUCTION_SUBSTRUCTURE, p1=P1_NON_CONFIRM, p2=P2_NONE, data=b"\x00")
    assert exc_info.value.status == ErrorType.UNIMPLEMENTED_INSTRUCTION


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
