# A Password Manager for Ledger Devices

A simple password manager application for Ledger devices, with command-line
interface similar to Unix pass. Works on Nano S, Nano S Plus and Nano X.

Up to 128 login/password entries can be stored. Passwords can be exported
encrypted to a file, and imported on another device sharing the same seed.

![Demo animation](doc/demo.gif)

This application is written in Rust and C.

[Implementation details](doc/impl.md)

## Usage

The client script `nanopass.py` must be used to interact with the application
to:
- list stored passwords,
- retrieve passwords,
- insert or generate new passwords,
- update or delete passwords,
- export passwords to a JSON file,
- import passwords from a JSON file.

The application can also be used with the dedicated [chrome extension](https://github.com/LedgerHQ/nanopass-chrome-ext).

## Prerequisites

* Install [cargo-ledger](https://github.com/LedgerHQ/cargo-ledger): `cargo install --git https://github.com/LedgerHQ/cargo-ledger`
* Run `cargo ledger setup`
* Install `arm-none-eabi-gcc` from <https://developer.arm.com/downloads/-/gnu-rm>

## Building and installing

You can use
[cargo-ledger](https://github.com/ledgerhq/cargo-ledger) which
builds, outputs a `hex` file and a manifest file for `ledgerctl`, and loads it
on a device in a single `cargo ledger build nanos --load` command in your app directory.

## License

Licensed under Apache-2.0 license.

[Tiny-AES](https://github.com/kokke/tiny-AES-c) library is included and is under
The Unlicense.
