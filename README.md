# pk-crypt

## Introduction

CLI tool to decrypt and encrypt `.pk` files that are part of configuration files for KalOnline game.

## Usage

`pk-crypt [OPTIONS] <MODE>`

### Options

* -p, --password <PASSWORD> - .pk password [default: `EV)O8@BL$3O2E`]
* -x, --xor <XOR> - Xor decrypt/encrypt key (decimal), range of this value is dependent on DECRYPT/ENCRYPT lookup tables [default: `47`]
* -f, --file <FILE> - File to be decrypted/encrypted. Files will be decrypted to {filename}_decrypted. The same folder is used as input in encrypt mode [default: `config.pk`]
* -h, --help - Print help (see a summary with '-h')
* -V, --version - Print version

### Modes

* decrypt
* encrypt

## Example usage

### Decrypt

`pk-cypt.exe decrypt --file config.pk --password abcd1234 --xor 45`

### Encrypt

`pk-cypt.exe encrypt --file config.pk --password abcd1234 --xor 45`
