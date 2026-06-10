import pytest
import time

from application_client.solana import ErrorType
from ragger.firmware import Firmware


class TestMockReview:

    @pytest.mark.parametrize("contract_id", [1, 2, 3, 4, 5])
    @pytest.mark.parametrize("version", [1, 2])
    def test_mock_review(self, sol, scenario_navigator, root_pytest_dir, contract_id, version):
        suffix = f"c{contract_id}_v{version}"
        with sol.send_mock_review(contract_id, version):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name=suffix)

        assert sol.get_async_response().status == 0x9000

    def test_mock_review_click_alias(self, sol, backend, firmware, scenario_navigator,
                                     root_pytest_dir):
        """Click the alias '>' icon on the first field of contract 1 v1 to open the info modal."""
        if firmware == Firmware.NANOS:
            pytest.skip("NanoS not supported")
        with sol.send_mock_review(1, 1):
            # Tap the '>' icon area on the first tag-value pair
            if firmware == Firmware.NANOX:
                # On Nano, press both buttons to open alias
                backend.both_click()
            else:
                # On touch devices (Stax/Flex/Apex), tap the right side of the first field
                backend.finger_touch(350, 180)
            time.sleep(0.5)
            # Navigate back from the info modal and approve
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name="c1_v1_click_alias",
                                              do_comparison=False)
