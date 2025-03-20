import base58
from pathlib import Path

from ragger.firmware import Firmware
from ragger.navigator import NavInsID, NavIns
from ragger.utils import create_currency_config
from ragger.bip import pack_derivation_path

ROOT_SCREENSHOT_PATH = Path(__file__).parent.parent.resolve()

### Some utilities functions for amounts conversions ###

def sol_to_lamports(sol_amount: int) -> int:
    return round(sol_amount * 10**9)


def lamports_to_bytes(lamports: int) -> str:
    hex:str = '{:x}'.format(lamports)
    if (len(hex) % 2 != 0):
        hex = "0" + hex
    return bytes.fromhex(hex)


### Proposed values for fees and amounts ###

AMOUNT          = sol_to_lamports(2.078)
AMOUNT_BYTES    = lamports_to_bytes(AMOUNT)

AMOUNT_2        = sol_to_lamports(101.000001234)
AMOUNT_2_BYTES  = lamports_to_bytes(AMOUNT_2)

FEES            = sol_to_lamports(0.00000564)
FEES_BYTES      = lamports_to_bytes(FEES)


### Proposed foreign and owned addresses ###
# "Foreign" Solana public key (actually the device public key derived on m/44'/501'/11111')
FOREIGN_ADDRESS_STR = "AxmUF3qkdz1zs151Q5WttVMkFpFGQPwghZs4d1mwY55d"
FOREIGN_ADDRESS     = FOREIGN_ADDRESS_STR.encode('utf-8')
FOREIGN_PUBLIC_KEY  = base58.b58decode(FOREIGN_ADDRESS)

# "Foreign" Solana public key (actually the device public key derived on m/44'/501'/11112')
FOREIGN_ADDRESS_2_STR   = "8bjDMujLMttbmkTtoFgfw2sPYchSzzcTCEPGYDaNs3nj"
FOREIGN_ADDRESS_2       = FOREIGN_ADDRESS_2_STR.encode('utf-8')
FOREIGN_PUBLIC_KEY_2    = base58.b58decode(FOREIGN_ADDRESS_2)

# Device Solana public key (derived on m/44'/501'/12345')
OWNED_ADDRESS_STR   = "3GJzvStsiYZonWE7WTsmt1BpWXkfcgWMGinaDwNs9HBc"
OWNED_ADDRESS       = OWNED_ADDRESS_STR.encode('utf-8')
OWNED_PUBLIC_KEY    = base58.b58decode(OWNED_ADDRESS)

JUP_MINT_ADDRESS_STR = "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"
JUP_MINT_ADDRESS     = JUP_MINT_ADDRESS_STR.encode('utf-8')
JUP_MINT_PUBLIC_KEY  = base58.b58decode(JUP_MINT_ADDRESS_STR)


### Proposed Solana derivation paths for tests ###

SOL_PACKED_DERIVATION_PATH      = pack_derivation_path("m/44'/501'/12345'")
SOL_PACKED_DERIVATION_PATH_2    = pack_derivation_path("m/44'/501'/0'/0'")


### Package this currency configuration in exchange format ###

SOL_CONF = create_currency_config("SOL", "Solana")


def enable_blind_signing(navigator, firmware, snapshots_name: str):
    if firmware.is_nano:
        nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
               NavInsID.BOTH_CLICK, # Select blind signing
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Enable
               NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
              ]
    else:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
               NavIns(NavInsID.TOUCH, (348,132)),
               NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)

def enable_short_public_key(navigator, device_name: str, snapshots_name: str):
    if device_name.startswith("nano"):
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
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)

def enable_expert_mode(navigator, firmware, snapshots_name: str):
    if firmware.is_nano:
        nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
               NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Select Expert mode
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # expert
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
              ]
    elif firmware is Firmware.STAX:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
               NavIns(NavInsID.TOUCH, (348,382)),
               NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    elif firmware is Firmware.FLEX:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
               NavIns(NavInsID.TOUCH, (250,430)),
               NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)
