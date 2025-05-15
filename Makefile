# ****************************************************************************
#    Ledger App Solana
#    (c) 2024 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
    # `THIS_DIR` must be resolved BEFORE any `include` directives
    THIS_DIR   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
		TARGET_SDK := $(shell ./util/read-last-sdk)
		BOLOS_SDK  := ${$(TARGET_SDK)}
endif

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "Solana"

# Application version
APPVERSION_M = 1
APPVERSION_N = 8
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Application source files
APP_SOURCE_PATH += src

# Application icons
ICON_NANOS = icons/nanos_app_solana.gif
ICON_NANOX = icons/nanox_app_solana.gif
ICON_NANOSP = icons/nanox_app_solana.gif
ICON_STAX = icons/stax_app_solana.gif
ICON_FLEX = icons/flex_app_solana.gif

# Application allowed derivation curves
CURVE_APP_LOAD_PARAMS = ed25519

# Application allowed derivation paths.
PATH_APP_LOAD_PARAMS = "44'/501'"   # purpose=coin(44) / coin_type=Solana(501)

# Setting to allow building variant applications
VARIANT_PARAM = COIN
VARIANT_VALUES = solana

# Enabling DEBUG flag will enable PRINTF and disable optimizations
# DEBUG = 1

########################################
#     Application custom permissions   #
########################################
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_STAX TARGET_FLEX))
HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
endif

########################################
# Swap features #
########################################
ENABLE_SWAP = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
DISABLE_STANDARD_APP_FILES = 1

# Allow usage of function from lib_standard_app/crypto_helpers.c
APP_SOURCE_FILES += ${BOLOS_SDK}/lib_standard_app/crypto_helpers.c
APP_SOURCE_FILES += ${BOLOS_SDK}/lib_standard_app/swap_utils.c
APP_SOURCE_FILES += ${BOLOS_SDK}/lib_standard_app/base58.c
CFLAGS           += -I${BOLOS_SDK}/lib_standard_app/

WITH_U2F?=0
ifneq ($(WITH_U2F),0)
    DEFINES         += HAVE_U2F HAVE_IO_U2F
    DEFINES         += U2F_PROXY_MAGIC=\"~SOL\"
		SDK_SOURCE_PATH += lib_u2f
endif

DEFINES += HAVE_SDK_TLV_PARSER

WITH_LIBSOL?=1
ifneq ($(WITH_LIBSOL),0)
    SOURCE_FILES += $(filter-out %_test.c,$(wildcard libsol/*.c))
    CFLAGS       += -Ilibsol/include
    CFLAGS       += -Ilibsol
    DEFINES      += HAVE_SNPRINTF_FORMAT_U
    DEFINES      += NDEBUG
endif

#######################################
# Trusted Name Test Mode              #
#######################################
TRUSTED_NAME_TEST_KEY ?= 0
ifneq ($(TRUSTED_NAME_TEST_KEY),0)
  DEFINES += TRUSTED_NAME_TEST_KEY
endif

FIXED_TLV_CHALLENGE ?= 0
ifneq ($(FIXED_TLV_CHALLENGE),0)
  DEFINES += FIXED_TLV_CHALLENGE
endif

include $(BOLOS_SDK)/Makefile.standard_app
