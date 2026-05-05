import pytest
from ragger.error import ExceptionRAPDU

from application_client.solana import ErrorType
from application_client import solana_utils as SOL


class TestDerivationPathEnforcement:
    """Test that the app enforces Solana derivation path policy (m/44'/501'/...).

    The OS already enforces this via PATH_APP_LOAD_PARAMS in the Makefile, but
    the app also enforces it independently as defense-in-depth. These tests
    verify the application-level enforcement.
    """

    def test_get_pubkey_wrong_coin_type_eth(self, sol):
        with pytest.raises(ExceptionRAPDU) as e:
            sol.get_public_key(SOL.ETH_PACKED_DERIVATION_PATH)
        assert e.value.status == ErrorType.SOLANA_INVALID_DERIVATION_PATH

    def test_get_pubkey_wrong_coin_type_btc(self, sol):
        with pytest.raises(ExceptionRAPDU) as e:
            sol.get_public_key(SOL.BTC_PACKED_DERIVATION_PATH)
        assert e.value.status == ErrorType.SOLANA_INVALID_DERIVATION_PATH

    def test_get_pubkey_wrong_purpose(self, sol):
        with pytest.raises(ExceptionRAPDU) as e:
            sol.get_public_key(SOL.WRONG_PURPOSE_PACKED_DERIVATION_PATH)
        assert e.value.status == ErrorType.SOLANA_INVALID_DERIVATION_PATH

    def test_get_pubkey_valid_path_succeeds(self, sol):
        # Sanity check: valid Solana paths still work
        pubkey = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH)
        assert len(pubkey) == 32

        pubkey2 = sol.get_public_key(SOL.SOL_PACKED_DERIVATION_PATH_2)
        assert len(pubkey2) == 32
