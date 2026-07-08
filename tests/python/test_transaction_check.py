import hashlib
import base58
import struct
import pytest

from solders.pubkey import Pubkey
from spl.token.constants import TOKEN_2022_PROGRAM_ID
from spl.token.instructions import get_associated_token_address
from solders.instruction import Instruction, AccountMeta

from ledgered.devices import DeviceType
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, NavIns

from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import SystemInstructionTransfer, Message, PROGRAM_ID_SYSTEM, V0OffchainMessage, verify_signature
from application_client import solana_utils as SOL

TRANSFER_CHECKED = 12

FAKE_HASH = b'\xff' * 32

# Solana chain IDs. Only mainnet-beta (900) is honored; any other is rejected.
SOLANA_MAINNET_CHAIN_ID = 900
SOLANA_TESTNET_CHAIN_ID = 902

DEFAULT_TX_CHECK_PARAMS = {
    "address": base58.b58encode(b'\x22' * 32),
    "tx_hash": b'\xab' * 32,
    "chain_id": SOLANA_MAINNET_CHAIN_ID,
    "risk": 0,
    "category": 0,
    "tiny_url": "https://ledger.com/tx",
}


class TestTransactionCheck:

    def test_transaction_check_disabled_by_default(self, backend, sol: SolanaClient):
        """TX check APDU should be rejected when setting is disabled (default)"""
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")
        with pytest.raises(ExceptionRAPDU) as e:
            sol.provide_transaction_check(**DEFAULT_TX_CHECK_PARAMS)
        assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

    def test_transaction_check_state_cleared_after_sign(self, backend, sol: SolanaClient,
                                                        navigation_helper, scenario_navigator, test_name):
        """TX check state should be cleared after signing, so a second sign without
        a new TX check APDU must not see stale validation data.
        Run with -s and grep for '[TX CHECK]' to verify:
        - First sign:  '[TX CHECK] Validation PASSED'
        - Second sign: '[TX CHECK] No transaction check data received' → W3C_ISSUE_WARN
        """
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")
        navigation_helper.enable_transaction_check()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        message = Message([instruction]).serialize()

        tx_hash = hashlib.sha256(message).digest()
        address = base58.b58encode(from_public_key)

        # First sign with matching TX check
        sol.provide_transaction_check(address=address,
                                      tx_hash=tx_hash,
                                      chain_id=SOLANA_MAINNET_CHAIN_ID,
                                      risk=0,
                                      category=0,
                                      tiny_url="https://ledger.com/tx")

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(test_name=test_name + "_first_sign")

        # Second sign: no new TX check sent - must show W3C_ISSUE_WARN
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(test_name=test_name + "_second_sign")

    @pytest.mark.parametrize('report_type', ["NA", "invalid_hash", "invalid_chain_id", "benign", "warn", "threat"])
    def test_transaction_check_accept(self, backend, sol: SolanaClient,
                                      navigation_helper, scenario_navigator, test_name, report_type):
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")
        navigation_helper.enable_transaction_check()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        message = Message([instruction]).serialize()

        if report_type != "NA":
            risk = {"invalid_hash": 0, "invalid_chain_id": 0, "benign": 0, "warn": 1, "threat": 2}[report_type]
            tx_hash = FAKE_HASH if report_type == "invalid_hash" else hashlib.sha256(message).digest()
            chain_id = SOLANA_TESTNET_CHAIN_ID if report_type == "invalid_chain_id" else SOLANA_MAINNET_CHAIN_ID
            sol.provide_transaction_check(
                address=base58.b58encode(from_public_key),
                tx_hash=tx_hash,
                chain_id=chain_id,
                risk=risk,
                category=0,
                tiny_url="https://ledger.com/tx"
            )

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            if report_type in ("warn", "threat"):
                scenario_navigator.review_approve_with_warning(test_name=test_name + f"_{report_type}")
            else:
                scenario_navigator.review_approve(test_name=test_name + f"_{report_type}")

    @pytest.mark.parametrize('report_type', ["NA", "invalid_hash", "invalid_chain_id", "benign", "warn", "threat"])
    @pytest.mark.parametrize('scenario', ["main", "review"])
    def test_transaction_check_warning_inspect(self, backend, sol: SolanaClient, root_pytest_dir,
                                               navigation_helper, navigator, test_name, report_type, scenario):
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")
        if scenario == "main":
            if report_type not in ("warn", "threat"):
                pytest.skip("No warning screen for this report_type type to inspect")
        navigation_helper.enable_transaction_check()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        message = Message([instruction]).serialize()

        if report_type != "NA":
            risk = {"invalid_hash": 0, "invalid_chain_id": 0, "benign": 0, "warn": 1, "threat": 2}[report_type]
            tx_hash = FAKE_HASH if report_type == "invalid_hash" else hashlib.sha256(message).digest()
            chain_id = SOLANA_TESTNET_CHAIN_ID if report_type == "invalid_chain_id" else SOLANA_MAINNET_CHAIN_ID
            sol.provide_transaction_check(
                address=base58.b58encode(from_public_key),
                tx_hash=tx_hash,
                chain_id=chain_id,
                risk=risk,
                category=0,
                tiny_url="https://ledger.com/tx"
            )

        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
                if scenario == "main":
                    nav = [
                        # Inspect QR code
                        NavInsID.USE_CASE_HOME_SETTINGS,
                        # Quit QR code
                        NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
                        # Reject TX
                        NavInsID.USE_CASE_CHOICE_CONFIRM,
                        # Dismiss modal
                        NavInsID.USE_CASE_STATUS_DISMISS
                    ]
                else:
                    nav = []
                    if report_type in ("warn", "threat"):
                        # Accept first warning
                        nav += [NavInsID.USE_CASE_CHOICE_REJECT]

                    # Accept the first warning screen, then inspect and reject the warning in the TX
                    nav += [
                        # Inspect review warning screen
                        NavInsID.USE_CASE_HOME_SETTINGS,
                    ]

                    # Inspect QR code
                    if report_type not in ("benign"):
                        if backend.device.type == DeviceType.APEX_P:
                            coordinates = (150, 100)
                        else:
                            coordinates = (260, 180)
                        nav += [
                            # Click on warning text
                            NavIns(NavInsID.TOUCH, coordinates),
                            # Quit QR code
                            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
                            # Quit warning details screen
                        ]
                    nav += [
                        NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
                        # Bottom left reject TX
                        NavInsID.USE_CASE_REVIEW_REJECT,
                        # Yes, reject
                        NavInsID.USE_CASE_CHOICE_CONFIRM,
                        # Dismiss modal
                        NavInsID.USE_CASE_STATUS_DISMISS
                    ]
                # Inspect and reject in the first warning screen
                navigator.navigate_and_compare(root_pytest_dir,
                                            test_name + f"_{report_type}_{scenario}",
                                            nav)

        assert e.value.status == ErrorType.USER_CANCEL

    def test_transaction_check_opt_in_accept(self, backend, navigation_helper, sol: SolanaClient):
        """Opt-in APDU after already opted-in: should respond immediately with current state"""
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")

        # First opt-in (accept)
        with sol.send_async_transaction_check_opt_in():
            navigation_helper.accept_choice()

        # Second opt-in: should respond immediately (no UI)
        response = sol.request_transaction_check_opt_in()
        assert response[0] == 1  # tx_check_enable is True

    def test_transaction_check_opt_in_decline(self, backend, navigation_helper, sol: SolanaClient):
        """Opt-in APDU when not yet opted-in: user taps 'Maybe later' -> tx_check_enable=0"""
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")

        with sol.send_async_transaction_check_opt_in():
            navigation_helper.reject_choice()

        # Verify it's actually off: TX check APDU must be rejected
        with pytest.raises(ExceptionRAPDU) as e:
            sol.provide_transaction_check(**DEFAULT_TX_CHECK_PARAMS)
        assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

    def test_transaction_check_with_hook_warning(self, backend, sol: SolanaClient,
                                                 navigation_helper, scenario_navigator):
        """TX check risk warning combined with Transfer Hook should show both warnings.
        The flow is: hook choice screen -> W3C risk warning -> review -> sign.
        Both warning systems must coexist: the hook is a pre-review choice,
        and the W3C warning is part of the NBGL advanced review flow."""
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")
        navigation_helper.enable_transaction_check()

        # Build a Token2022 transfer_checked with hook account (5th account triggers hook warning)
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        receiver_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        mint_pubkey = Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
        sender_ata = get_associated_token_address(sender_public_key, mint_pubkey,
                                                  token_program_id=TOKEN_2022_PROGRAM_ID)
        destination_ata = get_associated_token_address(receiver_pubkey, mint_pubkey,
                                                       token_program_id=TOKEN_2022_PROGRAM_ID)
        hook_account = Pubkey.from_string("FcheSyMboM2FKxieZPsT7r69s5UunZiK8tNSmSKts92i")

        accounts = [
            AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=mint_pubkey, is_signer=False, is_writable=False),
            AccountMeta(pubkey=destination_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=sender_public_key, is_signer=True, is_writable=False),
            AccountMeta(pubkey=hook_account, is_signer=False, is_writable=True),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BQB", TRANSFER_CHECKED, 108, 6)
        )

        message_data = sol.craft_tx([transfer_instruction], sender_public_key)

        # Enroll ATA so the token can be resolved
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS,
                       str(destination_ata).encode('utf-8'),
                       SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))

        # Provide TX check with risk=1 (warning level) matching the transaction
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        tx_hash = hashlib.sha256(message_data).digest()
        address = base58.b58encode(from_public_key)

        sol.provide_transaction_check(address=address,
                                      tx_hash=tx_hash,
                                      chain_id=SOLANA_MAINNET_CHAIN_ID,
                                      risk=1,
                                      category=0x03,
                                      tiny_url="https://ledger.com/tx")

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve_with_warning(nb_warnings=2)

    def test_transaction_check_settings_toggle_flow(self, backend, sol: SolanaClient, test_name, navigation_helper, scenario_navigator):
        """End-to-end settings toggle flow:
        1. First toggle triggers consent screen (opt-in), accept it
        2. Second toggle disables directly (no consent), third re-enables directly
        3. Provide risk TX check, sign and verify 'Risk detected' warning
        4. Provide threat TX check, sign and verify 'Threat detected' warning
        """
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")

        # -- Step 1: First-time toggle → consent screen → accept → status dismiss --
        navigation_helper.enable_transaction_check(has_opt_in_modal=True, suffix="_toggle_on_consent")

        # -- Step 2: Toggle OFF (no consent screen) --
        navigation_helper.enable_transaction_check(has_opt_in_modal=False, suffix="_toggle_off")

        # Verify it's actually off: TX check APDU must be rejected
        with pytest.raises(ExceptionRAPDU) as e:
            sol.provide_transaction_check(**DEFAULT_TX_CHECK_PARAMS)
        assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

        # -- Step 3: Toggle back ON (no consent screen, already opted in) --
        navigation_helper.enable_transaction_check(has_opt_in_modal=False, suffix="_toggle_on_no_consent")

        # -- Step 4: Risk (risk=1) → review with "Risk detected" warning --
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        instruction = SystemInstructionTransfer(from_public_key, SOL.FOREIGN_PUBLIC_KEY, SOL.AMOUNT)
        message = Message([instruction]).serialize()

        sol.provide_transaction_check(address=base58.b58encode(from_public_key),
                                      tx_hash=hashlib.sha256(message).digest(),
                                      chain_id=SOLANA_MAINNET_CHAIN_ID,
                                      risk=1,
                                      category=0x03,
                                      tiny_url="https://ledger.com/tx")

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve_with_warning(test_name=test_name + "_risk_tx")

        # -- Step 5: Threat (risk=2) → review with "Threat detected" warning --
        sol.provide_transaction_check(address=base58.b58encode(from_public_key),
                                      tx_hash=hashlib.sha256(message).digest(),
                                      chain_id=SOLANA_MAINNET_CHAIN_ID,
                                      risk=2,
                                      category=0x02,
                                      tiny_url="https://ledger.com/tx")

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve_with_warning(test_name=test_name + "_threat_tx")

    def test_transaction_check_rejected_on_nano(self, backend, sol: SolanaClient):
        """TX check APDU should be rejected on Nano devices regardless of settings"""
        if not backend.device.is_nano:
            pytest.skip("This test is exclusive to Nano devices")
        with pytest.raises(ExceptionRAPDU) as e:
            sol.provide_transaction_check(**DEFAULT_TX_CHECK_PARAMS)
        assert e.value.status == ErrorType.UNIMPLEMENTED_INSTRUCTION

    def test_transaction_check_opt_in_rejected_on_nano(self, backend, sol: SolanaClient):
        """TX check opt-in APDU should be rejected on Nano devices"""
        if not backend.device.is_nano:
            pytest.skip("This test is exclusive to Nano devices")
        with pytest.raises(ExceptionRAPDU) as e:
            sol.request_transaction_check_opt_in()
        assert e.value.status == ErrorType.UNIMPLEMENTED_INSTRUCTION


class TestTransactionCheckBlindSigning:
    """Tests combining blind signing (unrecognized TX) with Transaction Check.
    Blind signing triggers when the transaction cannot be parsed/displayed clearly.
    When TX check is also enabled, both BLIND_SIGNING_WARN and W3C warning bits
    are set in the NBGL warning struct."""

    @staticmethod
    def _craft_blind_signing_tx(sol):
        """Create a transaction that triggers blind signing (unrecognized instruction)"""
        payer_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        tx = Instruction(
            program_id=Pubkey.from_string(PROGRAM_ID_SYSTEM),
            accounts=[
                AccountMeta(pubkey=payer_pubkey, is_signer=False, is_writable=False),
            ],
            data=struct.pack("<IQ", 0, 123456789),
        )
        return sol.craft_tx([tx], payer_pubkey)

    @pytest.mark.parametrize('report_type', ["NA", "invalid", "benign", "warn", "threat"])
    def test_transaction_check_blind_signing(self, backend, sol, navigation_helper, scenario_navigator, test_name, report_type):
        if backend.device.is_nano:
            pytest.skip("Not supported on Nano devices")
        navigation_helper.enable_blind_signing()
        navigation_helper.enable_transaction_check()

        message_data = self._craft_blind_signing_tx(sol)
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        if report_type != "NA":
            risk = {"invalid": 0, "benign": 0, "warn": 1, "threat": 2}[report_type]
            tx_hash = FAKE_HASH if report_type == "invalid" else hashlib.sha256(message_data).digest()
            sol.provide_transaction_check(
                address=base58.b58encode(from_public_key),
                tx_hash=tx_hash,
                chain_id=SOLANA_MAINNET_CHAIN_ID,
                risk=risk,
                category=0,
                tiny_url="https://ledger.com/tx"
            )

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve_with_warning(test_name=test_name + f"_{report_type}")


class TestTransactionCheckOffchainMessage:
    """Offchain message signing must never be affected by Transaction Checks.
    Even when TX Checks are enabled, OCMS should proceed without any W3C warning."""

    def test_transaction_check_offchain_message_ascii(self, backend, sol: SolanaClient,
                                                      navigation_helper, scenario_navigator, root_pytest_dir):
        """Sign an ASCII offchain message with TX Checks enabled.
        No W3C warning should appear — the flow should be identical to TX Checks disabled."""
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")
        navigation_helper.enable_transaction_check()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        offchain_message = V0OffchainMessage(b"Test message", from_public_key)
        message = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir)

        signature = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_transaction_check_offchain_message_with_stale_data(self, backend, sol: SolanaClient,
                                                                navigation_helper, scenario_navigator, root_pytest_dir):
        """Sign an offchain message after a TX check APDU was received (stale data).
        The offchain message flow must still not show any W3C warning."""
        if backend.device.is_nano:
            pytest.skip("Transaction Check not supported on Nano devices")
        navigation_helper.enable_transaction_check()

        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        # Send a TX check APDU (this data is for a transaction, not for the offchain message)
        sol.provide_transaction_check(
            address=base58.b58encode(from_public_key),
            tx_hash=FAKE_HASH,
            chain_id=SOLANA_MAINNET_CHAIN_ID,
            risk=2,
            category=0x02,
            tiny_url="https://ledger.com/tx"
        )

        # Now sign an offchain message - must not show any W3C warning despite stale TX check data
        offchain_message = V0OffchainMessage(b"Test message", from_public_key)
        message = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=root_pytest_dir)

        signature = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)
