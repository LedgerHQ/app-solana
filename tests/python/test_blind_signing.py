import pytest
import base58
import struct
from enum import IntEnum
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavIns, NavInsID, NavigateWithScenario

from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta

from application_client import solana_utils as SOL
from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import verify_signature, PROGRAM_ID_SYSTEM

class SystemInstruction(IntEnum):
    SystemCreateAccount = 0
    SystemAssign = 1
    SystemTransfer = 2
    SystemCreateAccountWithSeed = 3
    SystemAdvanceNonceAccount = 4
    SystemWithdrawNonceAccount = 5
    SystemInitializeNonceAccount = 6
    SystemAuthorizeNonceAccount = 7
    SystemAllocate = 8
    SystemAllocateWithSeed = 9
    SystemAssignWithSeed = 10



import time
payer_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

def _craft_blind_signing(sol):
    # Craft an unrecognized TX
    tx = Instruction(
        program_id=Pubkey.from_string(PROGRAM_ID_SYSTEM),
        accounts=[
            AccountMeta(pubkey=payer_pubkey, is_signer=False, is_writable=False),
            # No account to create
            # AccountMeta(pubkey=stake_account, is_signer=False, is_writable=True),
        ],
        data=struct.pack("<IQ", SystemInstruction.SystemCreateAccount, 123456789),
    )
    return sol.craft_tx([tx], payer_pubkey)

class TestBlindSigning:
    def _check_blind_signing_rejection(self, sol, message_data):
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                pass
        assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

    def test_blind_signing_disabled_go_to_settings(self, sol, backend, navigator, root_pytest_dir, test_name):
        if backend.device.is_nano:
            pytest.skip("This feature does not exist on Nano devices")

        self._check_blind_signing_rejection(sol, _craft_blind_signing(sol))
        navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.USE_CASE_CHOICE_CONFIRM,
                                                  validation_instructions=[NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                                                  text="^Blind signing$",
                                                  path=root_pytest_dir,
                                                  test_case_name=test_name)

    def test_blind_signing_disabled_go_to_menu(self, sol, backend, navigator, root_pytest_dir, test_name):
        if backend.device.is_nano:
            validation_instructions=[NavInsID.BOTH_CLICK]
            pattern = "Blind signing"
        else:
            validation_instructions=[NavInsID.USE_CASE_CHOICE_REJECT]
            pattern = "Enable blind signing"
        self._check_blind_signing_rejection(sol, _craft_blind_signing(sol))
        navigator.navigate_until_text_and_compare(navigate_instruction=None,
                                                  validation_instructions=validation_instructions,
                                                  text=pattern,
                                                  path=root_pytest_dir,
                                                  test_case_name=test_name)

def test_blind_signing_enabled_reject(sol, backend, scenario_navigator, navigator, navigation_helper, root_pytest_dir, test_name):
    navigation_helper.enable_blind_signing(test_name + "_enable_bs")
    message_data = _craft_blind_signing(sol)

    if backend.device.is_nano:
        navigate_instruction = NavInsID.RIGHT_CLICK
        pattern = "Reject transaction"
        validation_instructions = [NavInsID.BOTH_CLICK]
    else:
        # no need to navigate
        navigate_instruction = None
        pattern = "Back to safety"
        validation_instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM]

    with pytest.raises(ExceptionRAPDU) as e:
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigator.navigate_until_text_and_compare(navigate_instruction=navigate_instruction,
                                                      validation_instructions=validation_instructions,
                                                      text=pattern,
                                                      path=root_pytest_dir,
                                                      test_case_name=test_name + "_choice")
    assert e.value.status == ErrorType.USER_CANCEL

def test_blind_signing_enabled_accept(sol, backend, scenario_navigator, navigator, navigation_helper, root_pytest_dir, test_name):
    if backend.device.is_nano:
        navigate_instruction = NavInsID.RIGHT_CLICK
        warning_validation_instructions = [NavInsID.BOTH_CLICK]
        warning_pattern = "^Blind signing ahead$"
        approve_validation_instructions = [NavInsID.BOTH_CLICK]
        approve_pattern = "Accept risk"
    else:
        navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
        warning_validation_instructions = [NavInsID.USE_CASE_CHOICE_REJECT]
        warning_pattern = "^Continue anyway$"
        approve_validation_instructions = [NavInsID.USE_CASE_REVIEW_CONFIRM]
        approve_pattern = "^Hold to sign$"

    navigation_helper.enable_blind_signing(test_name + "_enable_bs")
    message_data = _craft_blind_signing(sol)

    with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
        navigator.navigate_until_text_and_compare(navigate_instruction=None,
                                                  validation_instructions=warning_validation_instructions,
                                                  text=warning_pattern,
                                                  path=root_pytest_dir,
                                                  test_case_name=test_name + "_choice")
        navigator.navigate_until_text_and_compare(navigate_instruction=navigate_instruction,
                                                  validation_instructions=approve_validation_instructions,
                                                  text=approve_pattern,
                                                  path=root_pytest_dir,
                                                  test_case_name=test_name + "_review",
                                                  screen_change_before_first_instruction=False)

def test_blind_signing_enabled_navigate_warnings(sol, backend, scenario_navigator, navigator, navigation_helper, root_pytest_dir, test_name):
    if backend.device.is_nano:
        pytest.skip("No warning to navigate on Nano devices")

    navigation_helper.enable_blind_signing(test_name + "_enable_bs")
    message_data = _craft_blind_signing(sol)

    with pytest.raises(ExceptionRAPDU) as e:
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.USE_CASE_HOME_SETTINGS,
                                                      validation_instructions=[NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                                                      text="Learn more",
                                                      path=root_pytest_dir,
                                                      test_case_name=test_name + "_warning_info")
            navigator.navigate_until_text_and_compare(navigate_instruction=None,
                                                      validation_instructions=[NavInsID.USE_CASE_CHOICE_REJECT],
                                                      text="Continue anyway",
                                                      path=root_pytest_dir,
                                                      test_case_name=test_name + "_warning_accept",
                                                      screen_change_before_first_instruction=False)
            navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.USE_CASE_HOME_SETTINGS,
                                                      validation_instructions=[NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                                                      text="Security report",
                                                      path=root_pytest_dir,
                                                      test_case_name=test_name + "_security_report",
                                                      screen_change_before_first_instruction=False)
            navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.SWIPE_CENTER_TO_LEFT,
                                                      validation_instructions=[NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM],
                                                      text="Hold to sign",
                                                      path=root_pytest_dir,
                                                      test_case_name=test_name + "_review",
                                                      screen_change_before_first_instruction=False)
    assert e.value.status == ErrorType.USER_CANCEL
