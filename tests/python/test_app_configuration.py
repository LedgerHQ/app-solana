from application_client.solana import SolanaClient


class TestAppConfiguration:

    @staticmethod
    def check_config(sol: SolanaClient, is_nano: bool,
                     blind_sign: int, pubkey_display: int,
                     tx_check_opt_in: int, tx_check_enable: int):
        config = sol.get_app_configuration()
        if is_nano:
            assert len(config) == 5
            assert list(config[:2]) == [blind_sign, pubkey_display]
        else:
            assert len(config) == 7
            assert list(config[:2]) == [blind_sign, pubkey_display]
            assert list(config[5:7]) == [tx_check_opt_in, tx_check_enable]

    def test_app_configuration(self, backend, sol: SolanaClient, navigation_helper):
        """Each setting toggle only affects its own flag in GetAppConfiguration"""
        is_nano = backend.device.is_nano

        self.check_config(sol, is_nano, 0, 0, 0, 0)

        navigation_helper.enable_blind_signing(suffix="_on")
        self.check_config(sol, is_nano, 1, 0, 0, 0)
        navigation_helper.enable_blind_signing(suffix="_off")
        self.check_config(sol, is_nano, 0, 0, 0, 0)

        navigation_helper.enable_short_public_key(suffix="_on")
        self.check_config(sol, is_nano, 0, 1, 0, 0)
        navigation_helper.enable_short_public_key(suffix="_off")
        self.check_config(sol, is_nano, 0, 0, 0, 0)

        if not is_nano:
            navigation_helper.enable_transaction_check(has_opt_in_modal=True, suffix="_on")
            self.check_config(sol, is_nano, 0, 0, 1, 1)
            # Disable tx check — opt_in stays, enable goes off
            navigation_helper.enable_transaction_check(has_opt_in_modal=False, suffix="_off")
            self.check_config(sol, is_nano, 0, 0, 1, 0)
