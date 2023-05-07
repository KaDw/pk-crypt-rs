# pk-crypt

## Introduction

CLI tool to decrypt and encrypt `.pk` files that are part of configuration files for KalOnline game.

[You can find latest release for Windows and Linux here](https://github.com/KaDw/pk-crypt-rs/releases/latest)

## Usage

`pk-crypt [OPTIONS] <MODE>`

### Options

* -p, --password_text <PASSWORD_TEXT> - .pk password, UTF-8 encoding
* --password-bytes <PASSWORD_BYTES> - .pk password as bytes, use hex format, eg. "pass" in UTF-8 is equal to "70617373"
* -x, --xor <XOR> - Xor decrypt/encrypt key (decimal), range of this value is dependent on DECRYPT/ENCRYPT lookup tables [default: `47`]
* -f, --file <FILE> - File to be decrypted/encrypted. Files will be decrypted to {filename}_decrypted. The same folder is used as input in encrypt mode [default: `config.pk`]
* -h, --help - Print help (see a summary with '-h')
* -V, --version - Print version

### Modes

* decrypt
* encrypt

## Example usage

### Decrypt

`pk-cypt.exe decrypt -f config.pk -p abcd1234 -x 45`

Decrypted config will be stored in `{filename}_decrypted`, in this case `config_decrypted`

### Encrypt

`pk-cypt.exe encrypt -f config.pk -p abcd1234 -x 45`

In this mode pk-crypt will look for `{filename}_decrypted` (config decrypted in this example) directory and create `config.pk` out of it

### Password as bytes

`pk-cypt.exe encrypt -f config.pk --password-bytes 70C47373 -x 45`

Under the hood unzip and zip functions use byte representation, not a string.

In this example pk-crypt will encrypt file using `0x70, 0xC4, 0x73, 0x73`  which is equivalent to text `pÄss` in Windows-1252 encoding.

Now let's assume we want to decrypt the file using `--password-text pÄss`. It won't work since by default UTF-8 encoding is used and `pÄss` UTF-8 byte representation is `0x70 0xC3 0xA4 0x73 0x73`. This are two completely different passwords!
