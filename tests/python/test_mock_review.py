import pytest

from application_client.solana import ErrorType


CONTRACTS = [
    (1, "token_transfer"),
    (2, "stake_delegation"),
    (3, "nft_purchase"),
    (4, "swap"),
    (5, "program_upgrade"),
]

VERSIONS = [1, 2]


class TestMockReview:

    @pytest.mark.parametrize("contract_id, contract_name", CONTRACTS)
    @pytest.mark.parametrize("version", VERSIONS)
    def test_mock_review(self, sol, scenario_navigator, root_pytest_dir,
                         contract_id, contract_name, version):
        suffix = f"{contract_name}_v{version}"
        with sol.send_mock_review(contract_id, version):
            scenario_navigator.review_approve(path=root_pytest_dir,
                                              test_name=suffix)

        assert sol.get_async_response().status == 0x9000
