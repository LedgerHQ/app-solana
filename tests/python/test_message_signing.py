import pytest
import struct
from ragger.error import ExceptionRAPDU

from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta

from application_client.solana import ErrorType
from application_client.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, PROGRAM_ID_SYSTEM
from application_client import solana_utils as SOL

class TestMessageSigning:

    def test_solana_simple_transfer_ok_1(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_ok_2(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH_2)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY_2, SOL.AMOUNT_2)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH_2, message):
            scenario_navigator.review_approve(path=root_pytest_dir)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_refused(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir)
        assert e.value.status == ErrorType.USER_CANCEL

    def test_system_create_account(self, sol, scenario_navigator, root_pytest_dir):
        from_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        new_account = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        # Use a non-well-known program so the owner is displayed on screen
        owner_program = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)

        create_account = Instruction(
            program_id=Pubkey.from_string(PROGRAM_ID_SYSTEM),
            accounts=[
                AccountMeta(pubkey=from_pubkey, is_signer=True, is_writable=True),
                AccountMeta(pubkey=new_account, is_signer=True, is_writable=True),
            ],
            # SystemCreateAccount: kind(u32) + lamports(u64) + space(u64) + owner(pubkey)
            data=struct.pack("<IQQ", 0, 2000000, 165) + bytes(owner_program),
        )

        message_data = sol.craft_tx([create_account], from_pubkey)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_system_create_account_with_seed(self, sol, scenario_navigator, root_pytest_dir):
        from_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        new_account = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        base_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        # Use a well-known program so the owner is NOT displayed on screen
        owner_program = Pubkey.from_string("Stake11111111111111111111111111111111111111")
        seed = b"stake:0"

        create_account_with_seed = Instruction(
            program_id=Pubkey.from_string(PROGRAM_ID_SYSTEM),
            accounts=[
                AccountMeta(pubkey=from_pubkey, is_signer=True, is_writable=True),
                AccountMeta(pubkey=new_account, is_signer=False, is_writable=True),
            ],
            # SystemCreateAccountWithSeed: kind(u32) + base(pubkey) + seed_len(u64) + seed + lamports(u64) + space(u64) + owner(pubkey)
            data=struct.pack("<I", 3)
                + bytes(base_pubkey)
                + struct.pack("<Q", len(seed))
                + seed
                + struct.pack("<QQ", 5000000, 200)
                + bytes(owner_program),
        )

        message_data = sol.craft_tx([create_account_with_seed], from_pubkey)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_solana_large_transaction_ok(self, sol, backend, navigation_helper, root_pytest_dir):
        # A transaction larger than the legacy on-chain packet size (1232 bytes) is received across
        # multiple APDU chunks (the reception buffer grows dynamically) and signed. No size cap is
        # enforced on transaction data.
        navigation_helper.enable_blind_signing()
        from_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        # Unrecognized program forces blind signing; the data padding pushes the message past 1232.
        unknown_program = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        big_instruction = Instruction(
            program_id=unknown_program,
            accounts=[AccountMeta(pubkey=from_pubkey, is_signer=False, is_writable=False)],
            data=b"\x00" * 2048,
        )
        message_data = sol.craft_tx([big_instruction], from_pubkey)
        assert len(message_data) > 1232, "test message must exceed the legacy 1232-byte packet size"

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_blind_signing_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_solana_oversized_transaction_rejected(self, sol):
        # There is no transaction size cap: the only size-based refusal is a reception buffer
        # allocation failure. A message too large for any single allocation is refused cleanly.
        from_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        unknown_program = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        oversized_instruction = Instruction(
            program_id=unknown_program,
            accounts=[AccountMeta(pubkey=from_pubkey, is_signer=False, is_writable=False)],
            data=b"\x00" * 40000,
        )
        message_data = sol.craft_tx([oversized_instruction], from_pubkey)
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                pass
        assert e.value.status == ErrorType.SOLANA_INVALID_MESSAGE_SIZE
