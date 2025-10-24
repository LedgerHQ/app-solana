
from ledger_app_clients.exchange.cal_helper import CurrencyConfiguration

from application_client import solana_utils as RLO

# Define a configuration for each currency used in our tests: native coins and tokens

# --8<-- [start:sol_conf]
# Solana and Solana tokens
SOL_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="RLO", conf=RLO.SOL_CONF, packed_derivation_path=RLO.SOL_PACKED_DERIVATION_PATH)
JUP_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="JUP", conf=RLO.JUP_CONF, packed_derivation_path=RLO.JUP_PACKED_DERIVATION_PATH)
SOL_USDC_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="USDC", conf=RLO.SOL_USDC_CONF, packed_derivation_path=RLO.SOL_USDC_PACKED_DERIVATION_PATH)
GORK_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="GORK", conf=RLO.GORK_CONF, packed_derivation_path=RLO.GORK_PACKED_DERIVATION_PATH)
# --8<-- [end:sol_conf]
