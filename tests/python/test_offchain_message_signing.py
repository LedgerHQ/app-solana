import pytest
from ragger.error import ExceptionRAPDU

from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage
from application_client import solana_utils as SOL

import random
import string

class TestOffchainMessageSigningV0:

    def test_sign_offchain_message_v0_ascii_ok(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_very_long_ascii_ok(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, SOL.LONG_VALID_ASCII, from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              custom_screen_text=r"(Sign message|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_ascii_refused(self, sol, scenario_navigator, root_pytest_dir):

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir)
        assert e.value.status == ErrorType.USER_CANCEL

    def test_sign_offchain_message_v0_ascii_message_too_long(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        INVALID_LONG_MESSAGE = ''.join(random.choices(string.ascii_letters, k=32*1024))
        INVALID_LONG_MESSAGE = INVALID_LONG_MESSAGE.encode("ascii")

        offchain_message: OffchainMessage = OffchainMessage(0, INVALID_LONG_MESSAGE, from_public_key)
        message: bytes = offchain_message.serialize()

        try:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                pass
            assert False, "Ledger accepted too long message"
        except ExceptionRAPDU as e:
            assert e.status == ErrorType.SOLANA_INVALID_MESSAGE_SIZE


    def test_sign_offchain_message_v0_ascii_expert_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_expert_mode(test_name + "_1")

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name=test_name + "_2",
                                              custom_screen_text=r"(Sign message|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_ascii_expert_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_expert_mode(test_name + "_1")

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message",from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir,
                                                 test_name=test_name + "_2")
        assert e.value.status == ErrorType.USER_CANCEL


    def test_sign_offchain_message_v0_utf8_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing(test_name + "_1")

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_very_long_utf8_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing(test_name + "_1")

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Decode to a UTF-8 string, ignoring invalid characters
        VALID_LONG_MESSAGE = SOL.LONG_VALID_UTF8.encode("utf-8")

        offchain_message: OffchainMessage = OffchainMessage(0, VALID_LONG_MESSAGE, from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_utf8_too_long(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Generate 2048 random bytes
        random_bytes = bytes(random.randint(0, 255) for _ in range(32*1024))

        # Decode to a UTF-8 string, ignoring invalid characters
        INVALID_LONG_MESSAGE = random_bytes.decode("utf-8", errors="ignore").encode("utf-8")

        offchain_message: OffchainMessage = OffchainMessage(0, INVALID_LONG_MESSAGE, from_public_key)
        message: bytes = offchain_message.serialize()

        try:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                pass
            assert False, "Ledger accepted too long message"
        except ExceptionRAPDU as e:
            assert e.status == ErrorType.SOLANA_INVALID_MESSAGE_SIZE


    def test_sign_offchain_message_v0_with_app_domain_utf8_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing(test_name + "_1")

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Tęśtową wiądómóścią", 'utf-8'), from_public_key, b"My Candy App")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name=test_name + "_2",
                                              custom_screen_text=r"(Sign message|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_utf8_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing(test_name + "_1")

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir,
                                                 test_name=test_name + "_2")
        assert e.value.status == ErrorType.USER_CANCEL


    def test_sign_offchain_message_v0_utf8_expert_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing(test_name + "_1")
        navigation_helper.enable_expert_mode(test_name + "_2")

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name=test_name + "_3",
                                              custom_screen_text=r"(Sign message|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_utf8_expert_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing(test_name + "_1")
        navigation_helper.enable_expert_mode(test_name + "_2")

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'),from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir,
                                                 test_name=test_name + "_3")
        assert e.value.status == ErrorType.USER_CANCEL
