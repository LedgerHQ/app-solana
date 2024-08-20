[![Build Status](https://travis-ci.org/solana-labs/ledger-app-solana.svg?branch=master)](https://travis-ci.org/solana-labs/ledger-app-solana)

# Solana app for Ledger Wallet

## Overview

This app adds support for the Solana native token to Ledger Nano S hardware wallet.

Current Features:
- Pubkey queries
- Parse, display and sign all Solana CLI generated transaction formats
- Blind sign arbitrary transactions (Enabled via settings)

## Prerequisites
### For building the app
* [Install Docker](https://docs.docker.com/get-docker/)
* For Linux hosts, install the Ledger Nano [udev rules](https://github.com/LedgerHQ/udev-rules)
#### Get the [Ledger App Builder](https://developers.ledger.com/docs/nano-app/build/) Docker image
1. Pull the docker image
```bash
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder
```
2. Tag the docker image
```bash
docker image tag ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder ledger-app-builder
```
  * If permissions errors are encountered, ensure that your user is in the `docker`
group and that the session has been restarted

### For working with the device
#### Install Python3 PIP
Ubuntu Linux:
```
sudo apt install pip3
```
MacOS
```
brew install python3
```
#### Install ledgerblue python module
```
pip3 install ledgerblue
```
#### Locally clone SDK repos corresponding to those included in the Docker image
* Setup environment
```bash
cat >>"${HOME}"/.profile <<EOF
LEDGER_SDK_BASE_PATH= # set to a writable path
: "${LEDGER_SDK_BASE_PATH:?}"
export NANOS_SDK="${LEDGER_SDK_BASE_PATH}"/nanos-secure-sdk
export NANOX_SDK="${LEDGER_SDK_BASE_PATH}"/nanox-secure-sdk
export NANOSP_SDK="${LEDGER_SDK_BASE_PATH}"/nanosplus-secure-sdk
EOF
```
* Update the current session's environment
```bash
. "${HOME}"/.profile # Or close and reopen your terminal
```
* Clone the repositories
```bash
# Nano S SDK
git clone --branch 2.1.0 --depth 1 https://github.com/LedgerHQ/nanos-secure-sdk.git "${NANOS_SDK}"

# Nano X SDK
git clone --branch 2.0.2-2 --depth 1 https://github.com/LedgerHQ/nanox-secure-sdk.git "${NANOX_SDK}"

# Nano S+ SDK
git clone --branch 1.0.3 --depth 1 https://github.com/LedgerHQ/nanosplus-secure-sdk.git "${NANOSP_SDK}"
```

### For running the test suite
* [Rust](https://rustup.rs/)
* Solana [system dependencies](https://github.com/solana-labs/solana/#1-install-rustc-cargo-and-rustfmt)

## Build
It is highly recommended that you read and understand the [Ledger App Builder](https://developers.ledger.com/docs/embedded-app/build-app/#2-build-the-application)
build process before proceeding.  A convenience wrapper script (`./docker-make`) has been provided for simplicity

`docker-make` manages the current target SDK for you, automatically setting `BOLOS_SDK` to the
correct path when the Docker container is launched. A `TARGET_SDK` must be specified when building
from clean and clean must be run _before_ switching
#### `TARGET_SDK`
|Moniker|Device|
|:-----:|:-----|
|s|Nano S|
|x|Nano X|
|sp|Nano S+|
|stax|Stax|

```bash
./docker-make <TARGET_SDK>
```

### Clean
```bash
./docker-make clean
```

## Working with the device
Requires that the `BOLOS_SDK` envvar [be set](https://developers.ledger.com/docs/embedded-app/build-app/#b-build-the-application).
This can be achieved by first [building](#build) for the desired target device.
### Load
```bash
make load-only
```

### Delete
```bash
make delete
```

## Test
### Unit
Run C tests:
```bash
make -C libsol
```
### Integration
First enable `blind-signing` in the App settings
```bash
cargo run --manifest-path tests/Cargo.toml
```
