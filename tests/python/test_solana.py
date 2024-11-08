from ragger.backend import RaisePolicy
from ragger.utils import RAPDU

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage
from .apps.solana_utils import FOREIGN_PUBLIC_KEY, FOREIGN_PUBLIC_KEY_2, AMOUNT, AMOUNT_2, SOL_PACKED_DERIVATION_PATH, SOL_PACKED_DERIVATION_PATH_2, ROOT_SCREENSHOT_PATH
from .apps.solana_utils import enable_blind_signing, enable_expert_mode


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


    def test_ledger_sign_offchain_message_utf8_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_utf8_expert_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")
        enable_expert_mode(navigator, backend.firmware, test_name + "_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_3")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_utf8_expert_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")
        enable_expert_mode(navigator, backend.firmware, test_name + "_2")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_3")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

# Values used across Trusted Name test
CHAIN_ID = 101
ADDRESS = bytes.fromhex("606501b302e1801892f80a2979f585f8855d0f2034790a2455f744fac503d7b5")
TRUSTED_NAME = bytes.fromhex("276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9db")
SOURCE_CONTRACT = bytes.fromhex("c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61")

class TestTrustedName:

    def test_solana_trusted_name(self, backend, scenario_navigator):
        sol = SolanaClient(backend)

        challenge = sol.get_challenge()

        sol.provide_trusted_name(SOURCE_CONTRACT,
                                 TRUSTED_NAME,
                                 ADDRESS,
                                 CHAIN_ID,
                                 challenge=challenge)




                
