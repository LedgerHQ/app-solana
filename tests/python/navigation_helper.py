from pathlib import Path

from ragger.navigator import Navigator, NavIns, NavInsID, NavigateWithScenario
from ragger.firmware import Firmware
from ragger.backend import BackendInterface

class NavigationHelper:
    def __init__(self, backend: BackendInterface, firmware: Firmware, navigator: Navigator, scenario_navigator: NavigateWithScenario, test_name: str, root_pytest_dir: str):
        self._backend = backend
        self._firmware = firmware
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
            self._scenario_navigator.review_approve(path=self._root_pytest_dir, test_name=self.snapshots_dir_name)
        else:
            self._navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.SWIPE_CENTER_TO_LEFT,
                                                            validation_instructions=[NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL],
                                                            text="^Continue anyway$",
                                                            path=self._root_pytest_dir,
                                                            test_case_name=self.snapshots_dir_name + "_warning")
            # Approve review
            self._navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.SWIPE_CENTER_TO_LEFT,
                                                            validation_instructions=[NavInsID.USE_CASE_REVIEW_CONFIRM],
                                                            text="^Hold to sign$",
                                                            path=self._root_pytest_dir,
                                                            test_case_name=self.snapshots_dir_name + "_review",
                                                            screen_change_before_first_instruction=False)

    def navigate_with_warning_and_reject(self):
        if self._backend.firmware.is_nano:
            self._scenario_navigator.review_reject(path=self._root_pytest_dir, test_name=self.snapshots_dir_name)
        else:
            self._navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.SWIPE_CENTER_TO_LEFT,
                                                            validation_instructions=[NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM],
                                                            text="^Continue anyway$",
                                                            path=self._root_pytest_dir,
                                                            test_case_name=self.snapshots_dir_name + "_warning")

    def enable_blind_signing(self, snapshots_name: str):
        if self._firmware.is_nano:
            nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
                   NavInsID.BOTH_CLICK, # Select blind signing
                   NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Enable
                   NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
                  ]
        else:
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavIns(NavInsID.TOUCH, (348,132)),
                   NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
        self._navigator.navigate_and_compare(self._root_pytest_dir,
                                             snapshots_name,
                                             nav,
                                             screen_change_before_first_instruction=False)

    def enable_short_public_key(self, snapshots_name: str):
        if self._firmware.is_nano:
            nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
                   NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Select public key length
                   NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # short
                   NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
                  ]
        else:
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavInsID.USE_CASE_SETTINGS_NEXT,
                   NavIns(NavInsID.TOUCH, (348,251)),
                   NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
        self._navigator.navigate_and_compare(self._root_pytest_dir,
                                             snapshots_name,
                                             nav,
                                             screen_change_before_first_instruction=False)

    def enable_expert_mode(self, snapshots_name: str):
        if self._firmware.is_nano:
            nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
                   NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Select Expert mode
                   NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # expert
                   NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
                  ]
        elif self._firmware is Firmware.STAX:
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavIns(NavInsID.TOUCH, (348,382)),
                   NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
        elif self._firmware is Firmware.FLEX:
            nav = [NavInsID.USE_CASE_HOME_SETTINGS,
                   NavInsID.USE_CASE_SETTINGS_NEXT,
                   NavIns(NavInsID.TOUCH, (250,150)),
                   NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
        self._navigator.navigate_and_compare(self._root_pytest_dir,
                                             snapshots_name,
                                             nav,
                                             screen_change_before_first_instruction=False)
