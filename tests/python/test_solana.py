from ragger.backend import RaisePolicy
from ragger.utils import RAPDU

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage, \
    ComputeBudgetInstructionUnitLimit, ComputeBudgetSetComputeUnitPrice
from .apps.solana_utils import FOREIGN_PUBLIC_KEY, FOREIGN_PUBLIC_KEY_2, AMOUNT, AMOUNT_2, SOL_PACKED_DERIVATION_PATH, \
    SOL_PACKED_DERIVATION_PATH_2, ROOT_SCREENSHOT_PATH, COMPUTE_BUDGET_UNIT_LIMIT, COMPUTE_BUDGET_UNIT_PRICE
from .apps.solana_utils import enable_blind_signing, enable_short_public_key, enable_expert_mode, navigation_helper_confirm, navigation_helper_reject


class TestGetPublicKey:

    def test_solana_get_public_key_ok(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            if backend.firmware.device.startswith("nano"):
                navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                          [NavInsID.BOTH_CLICK],
                                                          "Approve",
                                                          ROOT_SCREENSHOT_PATH,
                                                          test_name)
            else:
                instructions = [
                    NavInsID.USE_CASE_REVIEW_TAP,
                    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ]
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                               test_name,
                                               instructions)

        assert sol.get_async_response().data == from_public_key

    def test_solana_get_public_key_refused(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            if backend.firmware.device.startswith("nano"):
                navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                          [NavInsID.BOTH_CLICK],
                                                          "Reject",
                                                          ROOT_SCREENSHOT_PATH,
                                                          test_name)
            else:
                instructions = [
                    NavInsID.USE_CASE_REVIEW_TAP,
                    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ]
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                               test_name,
                                               instructions)

        assert sol.get_async_response().status == ErrorType.USER_CANCEL


class TestGetPublicKey:

    def test_solana_get_public_key_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            scenario_navigator.address_review_approve(path=ROOT_SCREENSHOT_PATH)

        assert sol.get_async_response().data == from_public_key


    def test_solana_get_public_key_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            scenario_navigator.address_review_reject(path=ROOT_SCREENSHOT_PATH)

        assert sol.get_async_response().status == ErrorType.USER_CANCEL


class TestMessageSigning:

    def test_solana_simple_transfer_ok_1(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_ok_2(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH_2)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY_2, AMOUNT_2)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH_2, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


class TestOffchainMessageSigning:

    def test_ledger_sign_offchain_message_ascii_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_ascii_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_ascii_expert_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_ascii_expert_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_utf8_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


class TestMessageSigning:

    def test_solana_simple_transfer_ok_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_solana_simple_transfer_ok_2(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH_2)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY_2, AMOUNT_2)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH_2, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_solana_simple_transfer_refused(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


class TestOffchainMessageSigning:

    def test_ledger_sign_offchain_message_ascii_ok(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_ledger_sign_offchain_message_ascii_refused(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_ledger_sign_offchain_message_ascii_expert_ok(self, backend, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware.device, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_ledger_sign_offchain_message_ascii_expert_refused(self, backend, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware.device, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name + "_2")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_ledger_sign_offchain_message_utf8_ok(self, backend, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware.device, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_ledger_sign_offchain_message_utf8_refused(self, backend, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware.device, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name + "_2")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_ledger_sign_offchain_message_utf8_expert_ok(self, backend, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware.device, test_name + "_1")
        enable_expert_mode(navigator, backend.firmware.device, test_name + "_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name + "_3")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_ledger_sign_offchain_message_utf8_expert_refused(self, backend, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware.device, test_name + "_1")
        enable_expert_mode(navigator, backend.firmware.device, test_name + "_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name + "_3")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

