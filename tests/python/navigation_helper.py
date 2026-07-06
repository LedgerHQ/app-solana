from pathlib import Path

from ragger.navigator import Navigator, NavIns, NavInsID, NavigateWithScenario
from ragger.firmware import Firmware
from ragger.backend import BackendInterface

class NavigationHelper:
    def __init__(self, backend: BackendInterface, navigator: Navigator, scenario_navigator: NavigateWithScenario, test_name: str, root_pytest_dir: str):
        self._backend = backend
        self._navigator = navigator
        self._scenario_navigator = scenario_navigator
        self._test_name = test_name
        self._test_name_suffix = ""
        self._root_pytest_dir = root_pytest_dir

    @property
    def snapshots_dir_name(self) -> str:
        return self._test_name + self._test_name_suffix

    def set_test_name_suffix(self, suffix: str):
        self._test_name_suffix = suffix

    def navigate_with_warning_and_accept(self):
        if self._backend.firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            warning_validation_instructions = [NavInsID.BOTH_CLICK]
            approve_validation_instructions = [NavInsID.BOTH_CLICK]
            approve_pattern = "^Sign transaction$"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            warning_validation_instructions = [NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL]
            approve_validation_instructions = [NavInsID.USE_CASE_REVIEW_CONFIRM]
            approve_pattern = "^Hold to sign$"

        # Dismiss warning
        self._navigator.navigate_until_text_and_compare(navigate_instruction=navigate_instruction,
                                                        validation_instructions=warning_validation_instructions,
                                                        text="^Continue anyway$",
                                                        path=self._root_pytest_dir,
                                                        test_case_name=self.snapshots_dir_name + "_warning")
        # Approve review
        self._navigator.navigate_until_text_and_compare(navigate_instruction=navigate_instruction,
                                                        validation_instructions=approve_validation_instructions,
                                                        text=approve_pattern,
                                                        path=self._root_pytest_dir,
                                                        test_case_name=self.snapshots_dir_name + "_review",
                                                        screen_change_before_first_instruction=False)


    def navigate_with_warning_and_reject(self):
        if self._backend.firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            reject_pattern = "^Back to safety$"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            # Accept warning == reject tx
            validation_instructions = [NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM]
            reject_pattern = "^Continue anyway$"

        self._navigator.navigate_until_text_and_compare(navigate_instruction=navigate_instruction,
                                                        validation_instructions=validation_instructions,
                                                        text=reject_pattern,
                                                        path=self._root_pytest_dir,
                                                        test_case_name=self.snapshots_dir_name + "_warning")

    def navigate_with_blind_signing_and_accept(self):
        if self._backend.device.is_nano:
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

        self._navigator.navigate_until_text_and_compare(navigate_instruction=None,
                                                        validation_instructions=warning_validation_instructions,
                                                        text=warning_pattern,
                                                        path=self._root_pytest_dir,
                                                        test_case_name=self._test_name + "_choice")
        self._navigator.navigate_until_text_and_compare(navigate_instruction=navigate_instruction,
                                                        validation_instructions=approve_validation_instructions,
                                                        text=approve_pattern,
                                                        path=self._root_pytest_dir,
                                                        test_case_name=self._test_name + "_review",
                                                        screen_change_before_first_instruction=False)

    def navigate_with_blind_signing_and_reject(self):
        if self._backend.device.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            pattern = "Reject transaction"
            validation_instructions = [NavInsID.BOTH_CLICK]
        else:
            # no need to navigate
            navigate_instruction = None
            pattern = "Back to safety"
            validation_instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM]
        self._navigator.navigate_until_text_and_compare(navigate_instruction=navigate_instruction,
                                                        validation_instructions=validation_instructions,
                                                        text=pattern,
                                                        path=self._root_pytest_dir,
                                                        test_case_name=self._test_name + "_choice")

    def _enable_nano_option_n(self, n):
        # initial: go to settings
        seq = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
        # move to option n (n-1 right clicks)
        seq += [NavInsID.RIGHT_CLICK] * (n - 1)
        # enable
        seq += [NavInsID.BOTH_CLICK]
        # go back to "back" screen
        seq += [NavInsID.RIGHT_CLICK] * (4 - n)
        # back to main menu
        seq += [NavInsID.BOTH_CLICK]
        # back to dashboard
        seq += [NavInsID.LEFT_CLICK]
        return seq

    def enable_blind_signing(self, suffix: str = ""):
        if self._backend.firmware.is_nano:
            nav = self._enable_nano_option_n(1)
        else:
            if self._backend.firmware is Firmware.APEX_P:
                coordinates = (263,95)
            else:
                coordinates = (348,132)
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavIns(NavInsID.TOUCH, coordinates),
                   NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
        self._navigator.navigate_and_compare(self._root_pytest_dir,
                                             self._test_name + "_enable_bs" + suffix,
                                             nav,
                                             screen_change_before_first_instruction=False)

    def enable_short_public_key(self, suffix: str = ""):
        if self._backend.firmware.is_nano:
            nav = self._enable_nano_option_n(2)
        else:
            if self._backend.firmware is Firmware.APEX_P:
                coordinates = (263,193)
            else:
                coordinates = (348,251)
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavIns(NavInsID.TOUCH, coordinates),
                   NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
        self._navigator.navigate_and_compare(self._root_pytest_dir,
                                             self._test_name + "_enable_spk" + suffix,
                                             nav,
                                             screen_change_before_first_instruction=False)

    def enable_expert_mode(self, suffix: str = ""):
        if self._backend.firmware.is_nano:
            nav = self._enable_nano_option_n(3)
        elif self._backend.firmware is Firmware.STAX:
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavIns(NavInsID.TOUCH, (348,382)),
                   NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
        else:
            if self._backend.firmware is Firmware.APEX_P:
                coordinates = (262,98)
            else:
                coordinates = (250,150)
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavInsID.USE_CASE_SETTINGS_NEXT,
                   NavIns(NavInsID.TOUCH, coordinates),
                   NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
        self._navigator.navigate_and_compare(self._root_pytest_dir,
                                             self._test_name + "_enable_em" + suffix,
                                             nav,
                                             screen_change_before_first_instruction=False)

    def enable_transaction_check(self, has_opt_in_modal: bool = True, suffix: str = ""):
        if self._backend.firmware.is_nano:
            raise NotImplementedError("Transaction Check setting is not available on Nano devices")
        else:
            if self._backend.firmware is Firmware.APEX_P:
                coordinates = (263,193)
            else:
                coordinates = (348,251)
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavInsID.USE_CASE_SETTINGS_NEXT,
                   NavIns(NavInsID.TOUCH, coordinates)]

            if has_opt_in_modal:
                # Opt-in consent screen appears on first toggle —
                # tap "Yes, enable" then dismiss the success status
                nav += [NavInsID.USE_CASE_CHOICE_CONFIRM,
                        NavInsID.USE_CASE_STATUS_DISMISS]

            # Exit settings
            nav += [NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]

        self._navigator.navigate_and_compare(self._root_pytest_dir,
                                             self._test_name + "_enable_tc" + suffix,
                                             nav,
                                             screen_change_before_first_instruction=False)

    def _choice_action(self, choice):
        self._navigator.navigate_and_compare(self._root_pytest_dir,
                                             self._test_name,
                                             [choice])

    def accept_choice(self):
        self._choice_action(NavInsID.USE_CASE_CHOICE_CONFIRM)

    def reject_choice(self):
        self._choice_action(NavInsID.USE_CASE_CHOICE_REJECT)
