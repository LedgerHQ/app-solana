import pytest
import base58

from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature
from application_client import solana_utils as SOL
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

from time import sleep

class TestDelayedSigning:
    """Tests for delayed signing feature (INS 0x08 preview + INS 0x09 sign)"""

    def test_delayed_signing_valid_flow(self, sol, backend, scenario_navigator, navigator, root_pytest_dir, test_name):
        """Test valid delayed signing: preview with zero blockhash, then sign with real blockhash"""
        # Get public key
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)

        # Step 1: Preview transaction with ZERO blockhash (INS 0x08)
        preview_tx = Message([instruction], recent_blockhash=bytes(32)).serialize()

        with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx):
            scenario_navigator.review_approve_with_spinner(spinner_text="Signing", path=root_pytest_dir)

        # Preview accepted, device has stored fingerprint
        assert len(sol.get_async_response().data) == 0

        # Step 2: Sign with REAL blockhash (INS 0x09) - instant, no UI
        real_blockhash = bytes([1] * 32)
        final_msg = Message([instruction], recent_blockhash=real_blockhash)
        final_tx = final_msg.serialize()

        # Delayed sign - instant, no UI
        signature = sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx).data
        verify_signature(from_public_key, final_tx, signature)

        if backend.device.is_nano:
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            validation_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_success_status",
                                       screen_change_before_first_instruction=False)

    def test_delayed_signing_two_consecutive_flows(self, sol, backend, navigator, scenario_navigator, root_pytest_dir, test_name):
        """Test two independent preview+delayed flows in sequence"""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # First flow
        instruction1 = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        preview_tx1 = Message([instruction1], recent_blockhash=bytes(32)).serialize()

        with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx1):
            scenario_navigator.review_approve_with_spinner(spinner_text="Signing",
                                                           path=root_pytest_dir,
                                                           test_name=test_name + "_1")

        real_blockhash1 = bytes([1] * 32)
        final_msg1 = Message([instruction1], recent_blockhash=real_blockhash1)
        final_tx1 = final_msg1.serialize()
        signature1 = sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx1).data
        verify_signature(from_public_key, final_tx1, signature1)

        if backend.device.is_nano:
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            validation_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_success_status",
                                       screen_change_before_first_instruction=False)

        # Second flow - different amount AND different blockhash
        instruction2 = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT_2)
        preview_tx2 = Message([instruction2], recent_blockhash=bytes(32)).serialize()

        with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx2):
            scenario_navigator.review_approve_with_spinner(spinner_text="Signing",
                                                           path=root_pytest_dir,
                                                           test_name=test_name + "_2")

        real_blockhash2 = bytes([2] * 32)
        final_msg2 = Message([instruction2], recent_blockhash=real_blockhash2)
        final_tx2 = final_msg2.serialize()
        signature2 = sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx2).data
        verify_signature(from_public_key, final_tx2, signature2)

        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_success_status",
                                       screen_change_before_first_instruction=False)

    def test_delayed_signing_preview_refused(self, sol, backend, navigator, scenario_navigator, root_pytest_dir):
        """Test delayed signing fails when preview was refused"""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        preview_tx = Message([instruction], recent_blockhash=bytes(32)).serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx):
                scenario_navigator.review_reject(path=root_pytest_dir)
        assert e.value.status == ErrorType.USER_CANCEL

        # Try delayed signing - should fail (no preview stored)
        final_msg = Message([instruction])
        final_tx = final_msg.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx)
        assert e.value.status == ErrorType.SOLANA_DELAYED_PREVIEW_NOT_FOUND

        if backend.device.is_nano:
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            validation_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_error_status",
                                       screen_change_before_first_instruction=False)

    def test_delayed_signing_no_preview(self, sol):
        """Test delayed signing fails when no preview was done"""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        final_msg = Message([instruction])
        final_tx = final_msg.serialize()

        # Try delayed signing without preview
        with pytest.raises(ExceptionRAPDU) as e:
            sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx)
        assert e.value.status == ErrorType.SOLANA_DELAYED_PREVIEW_NOT_FOUND

    def test_delayed_signing_twice_fails(self, sol, backend, navigator, scenario_navigator, root_pytest_dir):
        """Test that using delayed signing twice without new preview fails"""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        preview_tx = Message([instruction], recent_blockhash=bytes(32)).serialize()

        with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx):
            scenario_navigator.review_approve_with_spinner(spinner_text="Signing", path=root_pytest_dir)

        # First delayed sign - should work
        final_msg = Message([instruction])
        final_tx = final_msg.serialize()

        signature1 = sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx).data
        verify_signature(from_public_key, final_tx, signature1)

        if backend.device.is_nano:
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            validation_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_success_status",
                                       screen_change_before_first_instruction=False)

        # Second delayed sign - should fail (preview cleared)
        with pytest.raises(ExceptionRAPDU) as e:
            sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx)
        assert e.value.status == ErrorType.SOLANA_DELAYED_PREVIEW_NOT_FOUND

    def test_delayed_signing_different_amount_fails(self, sol, backend, navigator, scenario_navigator, root_pytest_dir):
        """Test attack: different amount in delayed message"""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Preview with AMOUNT
        instruction_preview = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        preview_tx = Message([instruction_preview], recent_blockhash=bytes(32)).serialize()

        with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx):
            scenario_navigator.review_approve_with_spinner(spinner_text="Signing", path=root_pytest_dir)

        # Try to sign with different amount
        instruction_attack = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT_2)
        final_msg = Message([instruction_attack])
        final_tx = final_msg.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx)
        assert e.value.status == ErrorType.SOLANA_DELAYED_HASH_MISMATCH

        if backend.device.is_nano:
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            validation_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_error_status",
                                       screen_change_before_first_instruction=False)

    def test_delayed_signing_different_recipient_fails(self, sol, backend, navigator, scenario_navigator, root_pytest_dir):
        """Test attack: different recipient in delayed message"""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Preview with FOREIGN_PUBLIC_KEY
        instruction_preview = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        preview_msg = Message([instruction_preview])
        preview_msg.recent_blockhash = bytes(32)
        preview_tx = preview_msg.serialize()

        with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx):
            scenario_navigator.review_approve_with_spinner(spinner_text="Signing", path=root_pytest_dir)

        # Try to sign with different recipient
        instruction_attack = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY_2, SOL.AMOUNT)
        final_msg = Message([instruction_attack])
        final_tx = final_msg.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx)
        assert e.value.status == ErrorType.SOLANA_DELAYED_HASH_MISMATCH

        if backend.device.is_nano:
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            validation_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_error_status",
                                       screen_change_before_first_instruction=False)

    def test_delayed_signing_different_derivation_path_fails(self, sol, backend, navigator, scenario_navigator, root_pytest_dir):
        """Test attack: different derivation path in delayed message"""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Preview with SOL_PACKED_DERIVATION_PATH
        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        preview_tx = Message([instruction], recent_blockhash=bytes(32)).serialize()

        with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx):
            scenario_navigator.review_approve_with_spinner(spinner_text="Signing", path=root_pytest_dir)

        # Try to sign the SAME message but with different derivation path
        final_tx = Message([instruction], recent_blockhash=bytes([1] * 32)).serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH_2, final_tx)
        assert e.value.status == ErrorType.SOLANA_DELAYED_DERIVATION_MISMATCH

        if backend.device.is_nano:
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            validation_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_error_status",
                                       screen_change_before_first_instruction=False)

    def test_delayed_signing_different_message_length_fails(self, sol, backend, navigator, scenario_navigator, root_pytest_dir):
        """Test attack: different message structure/length"""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Preview with simple transfer
        instruction_preview = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        preview_msg = Message([instruction_preview])
        preview_msg.recent_blockhash = bytes(32)
        preview_tx = preview_msg.serialize()

        with sol.send_async_sign_message_preview(SOL.SOL_PACKED_DERIVATION_PATH, preview_tx):
            scenario_navigator.review_approve_with_spinner(spinner_text="Signing", path=root_pytest_dir)

        # Try to sign with two instructions (different message length)
        instruction_attack1 = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT // 2)
        instruction_attack2 = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT // 2)
        final_msg = Message([instruction_attack1, instruction_attack2])
        final_tx = final_msg.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            sol.sign_previewed_message(SOL.SOL_PACKED_DERIVATION_PATH, final_tx)
        assert e.value.status == ErrorType.SOLANA_DELAYED_LENGTH_MISMATCH

        if backend.device.is_nano:
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            validation_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
        navigator.navigate_and_compare(path=root_pytest_dir,
                                       instructions=validation_instructions,
                                       test_case_name="delayed_signing_common_error_status",
                                       screen_change_before_first_instruction=False)
