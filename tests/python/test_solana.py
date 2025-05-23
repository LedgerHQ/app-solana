import pytest
from ragger.error import ExceptionRAPDU

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage
from .apps import solana_utils as SOL

import random
import string

class TestGetPublicKey:

    def test_solana_get_public_key_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        with sol.send_public_key_with_confirm(SOL.SOL_PACKED_DERIVATION_PATH):
            scenario_navigator.address_review_approve(path=SOL.ROOT_SCREENSHOT_PATH)

        assert sol.get_async_response().data == from_public_key


    def test_solana_get_public_key_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_public_key_with_confirm(SOL.SOL_PACKED_DERIVATION_PATH):
                scenario_navigator.address_review_reject(path=SOL.ROOT_SCREENSHOT_PATH)
        assert e.value.status == ErrorType.USER_CANCEL


class TestMessageSigning:

    def test_solana_simple_transfer_ok_1(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_ok_2(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH_2)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY_2, SOL.AMOUNT_2)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH_2, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=SOL.ROOT_SCREENSHOT_PATH)
        assert e.value.status == ErrorType.USER_CANCEL


class TestOffchainMessageSigning:

    def test_ledger_sign_offchain_message_ascii_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_very_long_message_ascii_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, SOL.LONG_VALID_ASCII, from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH,
                                              custom_screen_text=r"(Approve|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_ascii_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=SOL.ROOT_SCREENSHOT_PATH)
        assert e.value.status == ErrorType.USER_CANCEL

    def test_ledger_sign_offchain_message_ascii_message_too_long(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
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


    def test_ledger_sign_offchain_message_ascii_expert_ok(self, backend, scenario_navigator, navigator, test_name):
        SOL.enable_expert_mode(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH,
                                              test_name=test_name + "_2",
                                              custom_screen_text=r"(Approve|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_ascii_expert_refused(self, backend, scenario_navigator, navigator, test_name):
        SOL.enable_expert_mode(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message",from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=SOL.ROOT_SCREENSHOT_PATH,
                                                 test_name=test_name + "_2")
        assert e.value.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_utf8_ok(self, backend, scenario_navigator, navigator, test_name):
        SOL.enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_very_long_message_utf8_ok(self, backend, scenario_navigator, navigator, test_name):
        SOL.enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Decode to a UTF-8 string, ignoring invalid characters
        VALID_LONG_MESSAGE = SOL.LONG_VALID_UTF8.encode("utf-8")

        offchain_message: OffchainMessage = OffchainMessage(0, VALID_LONG_MESSAGE, from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_utf8_message_too_long(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
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


    def test_ledger_sign_offchain_message_with_app_domain_utf8_ok(self, backend, scenario_navigator, navigator, test_name):
        SOL.enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Tęśtową wiądómóścią", 'utf-8'), from_public_key, b"My Candy App")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH,
                                              test_name=test_name + "_2",
                                              custom_screen_text=r"(Approve|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_utf8_refused(self, backend, scenario_navigator, navigator, test_name):
        SOL.enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=SOL.ROOT_SCREENSHOT_PATH,
                                                 test_name=test_name + "_2")
        assert e.value.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_utf8_expert_ok(self, backend, scenario_navigator, navigator, test_name):
        SOL.enable_blind_signing(navigator, backend.firmware, test_name + "_1")
        SOL.enable_expert_mode(navigator, backend.firmware, test_name + "_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH,
                                              test_name=test_name + "_3",
                                              custom_screen_text=r"(Approve|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_utf8_expert_refused(self, backend, scenario_navigator, navigator, test_name):
        SOL.enable_blind_signing(navigator, backend.firmware, test_name + "_1")
        SOL.enable_expert_mode(navigator, backend.firmware, test_name + "_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'),from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=SOL.ROOT_SCREENSHOT_PATH,
                                                 test_name=test_name + "_3")
        assert e.value.status == ErrorType.USER_CANCEL
