from pathlib import Path

from ragger.navigator import Navigator, NavInsID, NavigateWithScenario
from ragger.backend import BackendInterface

ROOT_SCREENSHOT_PATH = Path(__file__).parent.parent.resolve()

class NavigationHelper:
    def __init__(self, backend: BackendInterface, navigator: Navigator, scenario_navigator: NavigateWithScenario, test_name: str):
        self._backend = backend
        self._navigator = navigator
        self._scenario_navigator = scenario_navigator
        self._test_name = test_name
        self._test_name_suffix = ""

    @property
    def snapshots_dir_name(self) -> str:
        return self._test_name + self._test_name_suffix

    def set_test_name_suffix(self, suffix: str):
        self._test_name_suffix = suffix

    def navigate_with_warning_and_accept(self):
        if self._backend.firmware.is_nano:
            self._scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=self.snapshots_dir_name)
        else:
            self._navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.SWIPE_CENTER_TO_LEFT,
                                                            validation_instructions=[NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL],
                                                            text="^Continue anyway$",
                                                            path=ROOT_SCREENSHOT_PATH,
                                                            test_case_name=self.snapshots_dir_name + "_warning")
            # Approve review
            self._navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.SWIPE_CENTER_TO_LEFT,
                                                            validation_instructions=[NavInsID.USE_CASE_REVIEW_CONFIRM],
                                                            text="^Hold to sign$",
                                                            path=ROOT_SCREENSHOT_PATH,
                                                            test_case_name=self.snapshots_dir_name + "_review",
                                                            screen_change_before_first_instruction=False)

    def navigate_with_warning_and_reject(self):
        if self._backend.firmware.is_nano:
            self._scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=self.snapshots_dir_name)
        else:
            self._navigator.navigate_until_text_and_compare(navigate_instruction=NavInsID.SWIPE_CENTER_TO_LEFT,
                                                            validation_instructions=[NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM],
                                                            text="^Continue anyway$",
                                                            path=ROOT_SCREENSHOT_PATH,
                                                            test_case_name=self.snapshots_dir_name + "_warning")
