from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta

from application_client import solana_utils as SOL
from application_client.solana_cmd_builder import verify_signature

# A program id that the app does not recognize: the transaction cannot be
# clear-signed and, with blind signing enabled, falls back to the raw view.
UNKNOWN_PROGRAM = Pubkey.from_bytes(bytes([9] * 32))
UNKNOWN_PROGRAM_2 = Pubkey.from_bytes(bytes([8] * 32))
OTHER_ACCOUNT = Pubkey.from_bytes(bytes([2] * 32))
THIRD_ACCOUNT = Pubkey.from_bytes(bytes([3] * 32))

payer_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)


def _craft_unknown_program_tx(sol):
    # Unknown program, two accounts (one signer/writable fee payer + one
    # read-only), and enough data to span more than one hex chunk.
    instruction = Instruction(
        program_id=UNKNOWN_PROGRAM,
        accounts=[
            AccountMeta(pubkey=payer_pubkey, is_signer=True, is_writable=True),
            AccountMeta(pubkey=OTHER_ACCOUNT, is_signer=False, is_writable=False),
        ],
        data=bytes(range(80)),  # > 64 bytes: exercises multi-chunk hex display
    )
    return sol.craft_tx([instruction], payer_pubkey)


def _craft_multi_instruction_tx(sol):
    # Two unknown-program instructions. Exercises the per-instruction page
    # breaks and the "Ix 1 .." / "Ix 2 .." enumeration, a read-only account, a
    # writable non-signer, a signer shared across both instructions, and a
    # second instruction whose data spans more than one hex chunk.
    ix1 = Instruction(
        program_id=UNKNOWN_PROGRAM,
        accounts=[
            AccountMeta(pubkey=payer_pubkey, is_signer=True, is_writable=True),
            AccountMeta(pubkey=OTHER_ACCOUNT, is_signer=False, is_writable=False),
        ],
        data=bytes(range(16)),
    )
    ix2 = Instruction(
        program_id=UNKNOWN_PROGRAM_2,
        accounts=[
            AccountMeta(pubkey=payer_pubkey, is_signer=True, is_writable=True),
            AccountMeta(pubkey=THIRD_ACCOUNT, is_signer=False, is_writable=True),
        ],
        data=bytes(range(80)),  # > 64 bytes: multi-chunk hex in the 2nd instruction
    )
    return sol.craft_tx([ix1, ix2], payer_pubkey)


def _enable_raw_view(navigation_helper):
    # The raw view is opt-in via Expert mode and requires blind signing.
    navigation_helper.enable_blind_signing()
    navigation_helper.enable_expert_mode()


def test_raw_signing_unknown_program_accept(sol, navigation_helper):
    _enable_raw_view(navigation_helper)
    message_data = _craft_unknown_program_tx(sol)
    with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
        navigation_helper.navigate_with_blind_signing_and_accept()
    signature = sol.get_async_response().data
    verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


def test_raw_signing_multiple_instructions_accept(sol, navigation_helper):
    _enable_raw_view(navigation_helper)
    message_data = _craft_multi_instruction_tx(sol)
    with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
        navigation_helper.navigate_with_blind_signing_and_accept()
    signature = sol.get_async_response().data
    verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)
