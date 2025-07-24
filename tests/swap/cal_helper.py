
from ledger_app_clients.exchange.cal_helper import CurrencyConfiguration

from application_client import solana_utils as SOL

# Define a configuration for each currency used in our tests: native coins and tokens

# --8<-- [start:sol_conf]
# Solana and Solana tokens
SOL_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="SOL", conf=SOL.SOL_CONF, packed_derivation_path=SOL.SOL_PACKED_DERIVATION_PATH)
JUP_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="JUP", conf=SOL.JUP_CONF, packed_derivation_path=SOL.JUP_PACKED_DERIVATION_PATH)
SOL_USDC_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="USDC", conf=SOL.SOL_USDC_CONF, packed_derivation_path=SOL.SOL_USDC_PACKED_DERIVATION_PATH)
GORK_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="GORK", conf=SOL.GORK_CONF, packed_derivation_path=SOL.GORK_PACKED_DERIVATION_PATH)
# --8<-- [end:sol_conf]
