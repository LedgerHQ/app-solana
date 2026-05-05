import pytest
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavIns, NavInsID, NavigateWithScenario

from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, V0OffchainMessage, V0MessageFormat, V1OffchainMessage
from application_client import solana_utils as SOL

import random
import string

class TestOffchainMessageBlindSigningDisabled:
    # We only test for v0 because the code behind is the same

    def _craft_utf8_v0_message(self, sol):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        offchain_message = V0OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        return offchain_message.serialize()

    def test_offchain_utf8_blind_signing_disabled_go_to_settings(self, sol, backend, navigator, root_pytest_dir, test_name):
        """When blind signing is disabled and a non-ASCII V0 message is sent, the error UI should offer to go to settings."""
        if backend.device.is_nano:
            pytest.skip("This feature does not exist on Nano devices")

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, self._craft_utf8_v0_message(sol)):
                navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.USE_CASE_CHOICE_CONFIRM,
                                                        validation_instructions=[NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                                                        text="^Blind signing$",
                                                        path=root_pytest_dir,
                                                        test_case_name=test_name)
        assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

    def test_offchain_utf8_blind_signing_disabled_go_to_menu(self, sol, backend, navigator, root_pytest_dir, test_name):
        """When blind signing is disabled and a non-ASCII V0 message is sent, the error UI should allow rejecting."""
        if backend.device.is_nano:
            validation_instructions=[NavInsID.BOTH_CLICK]
            pattern = "Blind signing"
        else:
            validation_instructions=[NavInsID.USE_CASE_CHOICE_REJECT]
            pattern = "Enable blind signing"
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, self._craft_utf8_v0_message(sol)):
                navigator.navigate_until_text_and_compare(navigate_instruction=None,
                                                        validation_instructions=validation_instructions,
                                                        text=pattern,
                                                        path=root_pytest_dir,
                                                        test_case_name=test_name)
        assert e.value.status == ErrorType.SDK_NOT_SUPPORTED


class TestOffchainMessageSigningV0:

    def test_sign_offchain_message_v0_ascii_ok(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_very_long_ascii_ok(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(SOL.LONG_VALID_ASCII, from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              custom_screen_text=r"(Sign message|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_ascii_refused(self, sol, scenario_navigator, root_pytest_dir):

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        offchain_message: V0OffchainMessage = V0OffchainMessage(b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir)
        assert e.value.status == ErrorType.USER_CANCEL

    def test_sign_offchain_message_v0_ascii_message_too_long(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        INVALID_LONG_MESSAGE = ''.join(random.choices(string.ascii_letters, k=32*1024))
        INVALID_LONG_MESSAGE = INVALID_LONG_MESSAGE.encode("ascii")

        offchain_message: V0OffchainMessage = V0OffchainMessage(INVALID_LONG_MESSAGE, from_public_key)
        message: bytes = offchain_message.serialize()

        try:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                pass
            assert False, "Ledger accepted too long message"
        except ExceptionRAPDU as e:
            assert e.status == ErrorType.SOLANA_INVALID_MESSAGE_SIZE


    def test_sign_offchain_message_v0_extended_utf8_format_rejected(self, sol, root_pytest_dir):
        """Format 2 (ExtendedUtf8) is not intended for HW wallet support and must be rejected."""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(
            b"Test message",
            from_public_key,
            format=V0MessageFormat.ExtendedUtf8
        )
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                pass
        assert e.value.status == ErrorType.SOLANA_INVALID_MESSAGE_HEADER


    def test_sign_offchain_message_v0_ascii_expert_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_expert_mode()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name=test_name + "_2",
                                              custom_screen_text=r"(Sign message|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_ascii_expert_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_expert_mode()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(b"Test message",from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir,
                                                 test_name=test_name + "_2")
        assert e.value.status == ErrorType.USER_CANCEL


    def test_sign_offchain_message_v0_utf8_ok(self, sol, backend, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper.navigate_with_blind_signing_and_accept()

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_very_long_utf8_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Decode to a UTF-8 string, ignoring invalid characters
        VALID_LONG_MESSAGE = SOL.LONG_VALID_UTF8.encode("utf-8")

        offchain_message: V0OffchainMessage = V0OffchainMessage(VALID_LONG_MESSAGE, from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper.navigate_with_blind_signing_and_accept()

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_utf8_too_long(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Generate 2048 random bytes
        random_bytes = bytes(random.randint(0, 255) for _ in range(32*1024))

        # Decode to a UTF-8 string, ignoring invalid characters
        INVALID_LONG_MESSAGE = random_bytes.decode("utf-8", errors="ignore").encode("utf-8")

        offchain_message: V0OffchainMessage = V0OffchainMessage(INVALID_LONG_MESSAGE, from_public_key)
        message: bytes = offchain_message.serialize()

        try:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                pass
            assert False, "Ledger accepted too long message"
        except ExceptionRAPDU as e:
            assert e.status == ErrorType.SOLANA_INVALID_MESSAGE_SIZE


    def test_sign_offchain_message_v0_with_app_domain_utf8_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(bytes("Tęśtową wiądómóścią", 'utf-8'), from_public_key, b"My Candy App")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper.navigate_with_blind_signing_and_accept()

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_utf8_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                navigation_helper.navigate_with_blind_signing_and_reject()
        assert e.value.status == ErrorType.USER_CANCEL


    def test_sign_offchain_message_v0_utf8_expert_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing()
        navigation_helper.enable_expert_mode()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper.navigate_with_blind_signing_and_accept()

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_sign_offchain_message_v0_utf8_expert_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        navigation_helper.enable_blind_signing()
        navigation_helper.enable_expert_mode()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message: V0OffchainMessage = V0OffchainMessage(bytes("Тестовое сообщение", 'utf-8'),from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                navigation_helper.navigate_with_blind_signing_and_reject()
        assert e.value.status == ErrorType.USER_CANCEL


class TestOffchainMessageSigningV1:
    """Tests for V1 offchain message signing (SRFC #3 simplified format)."""

    def test_sign_offchain_message_v1_ascii_ok(self, sol, scenario_navigator, root_pytest_dir):
        """Test signing a simple ASCII message with V1 format."""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage(b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_sign_offchain_message_v1_utf8_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        """Test signing a UTF-8 message with V1 format (blind signing required)."""
        navigation_helper.enable_blind_signing()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage("Hello 世界 🌍".encode('utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper.navigate_with_blind_signing_and_accept()

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_sign_offchain_message_v1_utf8_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        """Test rejecting a UTF-8 V1 message (blind signing enabled, user rejects at warning)."""
        navigation_helper.enable_blind_signing()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage("Hello 世界 🌍".encode('utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                navigation_helper.navigate_with_blind_signing_and_reject()
        assert e.value.status == ErrorType.USER_CANCEL

    def test_sign_offchain_message_v1_refused(self, sol, scenario_navigator, root_pytest_dir):
        """Test rejecting a V1 message."""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage(b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir)
        assert e.value.status == ErrorType.USER_CANCEL

    def test_sign_offchain_message_v1_ascii_expert_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        """Test signing ASCII V1 message in expert mode (exercises transaction_summary_finalize success path)."""
        navigation_helper.enable_expert_mode()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage(b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name=test_name + "_2",
                                              custom_screen_text=r"(Sign message|Hold to sign)")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_sign_offchain_message_v1_ascii_expert_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        """Test rejecting ASCII V1 message in expert mode."""
        navigation_helper.enable_expert_mode()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage(b"Test message", from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                scenario_navigator.review_reject(path=root_pytest_dir,
                                                 test_name=test_name + "_2")
        assert e.value.status == ErrorType.USER_CANCEL

    def test_sign_offchain_message_v1_utf8_expert_ok(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        """Test signing UTF-8 V1 message in expert mode (blind signing required)."""
        navigation_helper.enable_blind_signing()
        navigation_helper.enable_expert_mode()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper.navigate_with_blind_signing_and_accept()

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_sign_offchain_message_v1_utf8_expert_refused(self, sol, scenario_navigator, navigator, test_name, navigation_helper, root_pytest_dir):
        """Test rejecting UTF-8 V1 message in expert mode (blind signing required)."""
        navigation_helper.enable_blind_signing()
        navigation_helper.enable_expert_mode()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), from_public_key)
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                navigation_helper.navigate_with_blind_signing_and_reject()
        assert e.value.status == ErrorType.USER_CANCEL

    def test_sign_offchain_message_v1_duplicate_signers_rejected(self, sol):
        """V1 messages with duplicate signers must be rejected.

        Strict ascending lexicographic ordering on pubkeys implies uniqueness.
        Sending the same pubkey twice violates this invariant.
        """
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        offchain_message = V1OffchainMessage(b"Test message", [from_public_key, from_public_key])
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                pass
        assert e.value.status == ErrorType.SOLANA_INVALID_MESSAGE_HEADER

    def test_sign_offchain_message_v1_misordered_signers_rejected(self, sol):
        """V1 messages with signers not in strict ascending lexicographic order must be rejected."""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Create a pubkey that is lexicographically greater than any real pubkey
        high_pubkey = b'\xff' * 32

        # Place high_pubkey first, device pubkey second => descending order => must be rejected
        offchain_message = V1OffchainMessage(b"Test message", [high_pubkey, from_public_key])
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                pass
        assert e.value.status == ErrorType.SOLANA_INVALID_MESSAGE_HEADER

    def test_sign_offchain_message_v1_three_signers_misordered_rejected(self, sol):
        """V1 messages with three signers where ordering breaks in the middle must be rejected."""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Build three signers: low < high but device_pubkey placed after high
        # to ensure device key is present, then create disorder
        low_pubkey = b'\x00' * 32
        high_pubkey = b'\xff' * 32

        # Order: low, high, device_pubkey => high > device_pubkey for most real keys => misordered
        # But to be safe, just force disorder: low, device_pubkey, low_pubkey_bis
        # Simplest: put device key in the middle and have last < middle
        low_after = b'\x00' * 31 + b'\x01'  # very low, certainly < from_public_key

        offchain_message = V1OffchainMessage(b"Test message", [low_after, from_public_key, low_pubkey])
        message: bytes = offchain_message.serialize()

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                pass
        assert e.value.status == ErrorType.SOLANA_INVALID_MESSAGE_HEADER

    def test_sign_offchain_message_v1_two_signers_ordered_ok(self, sol, scenario_navigator, root_pytest_dir):
        """V1 message with two correctly ordered signers must be accepted."""
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        low_pubkey = b'\x01' + b'\x00' * 31
        # Ensure device pubkey sorts after low_pubkey by placing it second.
        # If from_public_key < low_pubkey, swap them.
        if from_public_key < low_pubkey:
            signers = [from_public_key, low_pubkey]
        else:
            signers = [low_pubkey, from_public_key]

        offchain_message = V1OffchainMessage(b"Test message", signers)
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)
