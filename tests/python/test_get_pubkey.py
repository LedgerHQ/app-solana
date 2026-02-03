import pytest
from ragger.error import ExceptionRAPDU

from application_client.solana import ErrorType
from application_client import solana_utils as SOL

class TestGetPublicKey:

    def test_solana_get_public_key_ok(self, sol, scenario_navigator, root_pytest_dir):
        from_public_key = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)

        with sol.send_public_key_with_confirm(SOL.SOL_PACKED_DERIVATION_PATH):
            scenario_navigator.address_review_approve(path=root_pytest_dir)

        assert sol.get_async_response().data == from_public_key


    def test_solana_get_public_key_refused(self, sol, scenario_navigator, root_pytest_dir):
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_public_key_with_confirm(SOL.SOL_PACKED_DERIVATION_PATH):
                scenario_navigator.address_review_reject(path=root_pytest_dir)
        assert e.value.status == ErrorType.USER_CANCEL
