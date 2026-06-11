import pytest
import time

from application_client.solana import ErrorType
from ragger.firmware import Firmware


class TestMockReview:

    @pytest.mark.parametrize("contract_id", [1, 2, 3, 4, 5, 6])
    @pytest.mark.parametrize("version", [1, 2])
    def test_mock_review(self, sol, scenario_navigator, root_pytest_dir, contract_id, version):
        suffix = f"test_mock_review_c{contract_id}_v{version}"
        with sol.send_mock_review(contract_id, version):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name=suffix)

        assert sol.get_async_response().status == 0x9000
