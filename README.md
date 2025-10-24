[![Build Status](https://travis-ci.org/solana-labs/ledger-app-solana.svg?branch=master)](https://travis-ci.org/solana-labs/ledger-app-solana)

# Rialo app for Ledger Wallet

## Overview

This app adds support for the Rialo native token to Ledger Nano S hardware wallet.

Current Features:
- Pubkey queries
- Parse, display and sign all Rialo CLI generated transaction formats
- Blind sign arbitrary transactions (Enabled via settings)

## Prerequisites

### For building the app

* [Install Docker](https://docs.docker.com/get-docker/)
* For Linux hosts, install the Ledger Nano [udev rules](https://github.com/LedgerHQ/udev-rules)
* Pull Ledger Development Tools image

```sh
$ docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

## Build

Build the app in the container. The BOLOS_SDK variable is used to specify the target SDK, allowing to compile the application for each Ledger device. See [Ledger Application Builder](https://github.com/LedgerHQ/ledger-app-builder?tab=readme-ov-file#compile-your-app-in-the-container) for more details.

```sh
# E.g. for Nano S
$ sudo docker run --rm -ti -v "$(realpath .):/app" --user $(id -u $USER):$(id -g $USER) ghcr.io/ledgerhq/ledger-app-builder//ledger-app-dev-tools:latest
bash$ BOLOS_SDK=$NANOS_SDK make
```

### Clean

Within the running development container

```sh
bash$ BOLOS_SDK=$NANOS_SDK make clean
```

## Working with the device

See [Ledger Application Builder](https://github.com/LedgerHQ/ledger-app-builder?tab=readme-ov-file#compile-your-app-in-the-container) for more details. 

### Load

```bash
$ sudo docker run --rm -ti  -v "$(realpath .):/app" --privileged -v "/dev/bus/usb:/dev/bus/usb" --user $(id -u $USER):$(id -g $USER) ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
bash$ BOLOS_SDK=$NANOS_SDK make load
```

### Delete

Within the running development container

```sh
bash$ BOLOS_SDK=$NANOS_SDK make delete
```

## Test

### Unit

Run C tests:

```sh
bash$ make -C libsol
```

### Ragger

Make sure that you have already built the application for the specific device.

Run Ragger tests:

```sh
# Install python test suite dependencies
bash$ pip install -r "tests/python/requirements.txt"

# Run test suite for the specific device, e.g. nanos
bash$ pytest tests/python/ --tb=short -v --device nanos -k ""
```

To regenerate golden snapshots, use `--golden_run` option.

### Integration

First enable `blind-signing` in the App settings

```sh
bash$ cargo run --manifest-path tests/Cargo.toml
```
