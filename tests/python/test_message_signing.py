import pytest
from ragger.error import ExceptionRAPDU

from application_client.solana import ErrorType
from application_client.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage
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
