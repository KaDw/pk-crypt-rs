# pk-crypt

## Introduction

CLI tool to decrypt and encrypt `.pk` files that are part of configuration files for KalOnline game.

[You can find latest release for Windows and Linux here](https://github.com/KaDw/pk-crypt-rs/releases/latest)

## Usage

### Decrypt

To `decrypt` the input file `config.pk` to the output directory `config_decrypted` 3 things are required:

1. Password also known as pk password.
2. Table what encrpytion table to use, `new` or `old`.
3. XOR key, it can be also recovered if user knows plaintext that is stored in a file

#### Decrypt with known XOR key

To decrypt using XOR key simply supply it using `-x` flag:

`pk-crypt.exe decrypt -i config.pk -o config_decrypted -p password -t new -x 45`

#### Decrypt and recover XOR key

Usually the XOR key is something not widely known. Key can be recovered only if plainfile wiht the known plaintext is supplied. To do so, use  `-F` followed by the filename (eg. `"TrainingCenter.dat"`) and  `-T` followed by plaintext that the file starts with (eg. `"<?xml version="`):

`pk-crypt.exe decrypt -i config.pk -o config_decrypted -p password -t new -F "TrainingCenter.dat" -T "<?xml version="`

After succesfull recovery the key will be printed as decimal value.

```
output
```

Try to use different encryption table if recovery failed.

From now on it might be more convinient to use XOR key itself.

### Encrypt

In encryption mode all 3 arguments, (password, table, xor key) specific to `.pk` file have to be supplied.

To `encrypt` the input directory `config_decrypted` to the output file `new_config.pk` use:

`pk-crypt.exe encrypt -i config_decrypted -o new_config.pk -p password -t new -x 45`

### Password representation

Let's assume we want to decrypt the file with password `pÄss`. Special characters (like `Ä`) might be encoded differently depeding on the character encoding. pk-crypt by default uses UTF-8 encoding and `pÄss` [UTF-8 byte representation](https://dencode.com/string/hex?v=p%C3%84ss&oe=UTF-8&nl=crlf&separator-each=1B&case=upper) is `0x70 0xC3 0xA4 0x73 0x73`. If someone used [Windows-1252 encoded](https://dencode.com/string/hex?v=p%C3%84ss&oe=windows-1252&nl=crlf&separator-each=1B&case=upper) password it's byte representation is `0x70, 0xC4, 0x73, 0x73`. Those are two completely different passwords!

Because under the hood unzip and zip functions use byte representation, not a string, in both `decrypt` or `encrypt` mode password can be supplied in two ways:

#### As text, UTF-8 encoded

The usual way:
`pk-crypt.exe decrypt -i config.pk -o config_decrypted --password-text pÄss -t new -x 45`

#### As bytes

In this example `pÄss` is supplied in Windows-1252 encoding:
`pk-crypt.exe decrypt -i config.pk -o config_decrypted --password-bytes 70C47373 -t new -x 45`
