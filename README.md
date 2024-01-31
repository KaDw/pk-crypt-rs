# pk-crypt

## Introduction

CLI tool to decrypt and encrypt .pk files that are part of the configuration files for KalOnline game.

[You can find the latest release for Windows and Linux here](https://github.com/KaDw/pk-crypt-rs/releases/latest)

## Usage

### Decrypt

To `decrypt` the input file `config.pk` to the output directory `config_decrypted` 3 things are required:

1. Pk password
2. Table - select between `new` or `old`.
3. XOR key - after unzipping the file with the correct password, it has to be decoded. For this process, the XOR key and table are required.

#### Decrypt with a known XOR key

To decrypt using the XOR key, simply supply it using the `-x` flag:

`pk-crypt.exe decrypt -i config.pk -o config_decrypted -p password -t new -x 45`

#### Decrypt and recover the XOR key

Usually, the XOR key is something not widely known. Key can be recovered only if a file with the known plaintext is supplied. To do so, use  `-F` followed by the filename (e.g. `"TrainingCenter.dat"`) and `-T` followed by the plaintext that the file starts with (e.g. `"<?xml version="`):

`pk-crypt.exe decrypt -i config.pk -o config_decrypted -p password -t new -F "TrainingCenter.dat" -T "<?xml version="`

After successful recovery, the key will be printed as a decimal value:

```text
Xor key recovered: 93
Decrypting config_org.pk to config_decrypted
Found 72 .dat files
Successfully decrypted config_decrypted
```

If recovery fails, try to switch between the `old` and `new` tables.

From now on, it might be more convenient to use the XOR key itself using the `-x` option

### Encrypt

In encryption mode, all three arguments (password, table and xor key) specific to the `.pk` file have to be supplied.

To `encrypt` the input directory `config_decrypted` to the output file `new_config.pk` use:

`pk-crypt.exe encrypt -i config_decrypted -o new_config.pk -p password -t new -x 45`

### Password representation

Let's assume we want to decrypt the file with the password `pÄss`. Special characters (like `Ä`) might be encoded differently depending on the character encoding. pk-crypt by default uses UTF-8 encoding and `pÄss` [UTF-8 byte representation](https://dencode.com/string/hex?v=p%C3%84ss&oe=UTF-8&nl=crlf&separator-each=1B&case=upper) is `0x70 0xC3 0xA4 0x73 0x73`. If someone used a [Windows-1252 encoded](https://dencode.com/string/hex?v=p%C3%84ss&oe=windows-1252&nl=crlf&separator-each=1B&case=upper) password, its byte representation is `0x70, 0xC4, 0x73, 0x73`. Those are two completely different passwords!

Because under the hood, unzip and zip functions use byte representations, not a string, in both `decrypt` or `encrypt` modes, password can be supplied in two ways:

#### As text, UTF-8 encoded

The usual way:
`pk-crypt.exe decrypt -i config.pk -o config_decrypted --password-text pÄss -t new -x 45`

#### As bytes

In this example, `pÄss` is supplied in Windows-1252 encoding:
`pk-crypt.exe decrypt -i config.pk -o config_decrypted --password-bytes 70C47373 -t new -x 45`

### Visual Studio Code integration

Since this tool doesn't have any integrated editor, you can use any editor you like. Visual Studio Code has a great feature - [tasks](https://code.visualstudio.com/docs/editor/tasks). It allows you to automate the whole process. To decrypt or encrypt, follow these steps:

1. Ctrl + Shift + P
2. Type run and look for `Tasks: Run Task`
3. Select `encrypt` or `decrypt`
4. Done!

Here is the example config that you must add to .vscode/tasks.json in order to have encrypt and decrypt tasks available under the `Tasks: Run Task`

```json
{
    // See https://go.microsoft.com/fwlink/?LinkId=733558
    // for the documentation about the tasks.json format
    "version": "2.0.0",
    "tasks": [
        {
            "label": "decrypt",
            "type": "process",
            "options": {
                "cwd": "${workspaceFolder}",
            },
            "command": "pk-crypt",
            "args": [
                "decrypt",
                "-i",
                "config.pk",
                "-o",
                "config_decrypted",
                "-p",
                "password",
                "-t",
                "new",
                "-x",
                "45"
            ]
        },
        {
            "label": "encrypt",
            "type": "process",
            "options": {
                "cwd": "${workspaceFolder}",
            },
            "command": "pk-crypt",
            "args": [
                "encrypt",
                "-i",
                "config_decrypted",
                "-o",
                "new_config.pk",
                "-p",
                "password",
                "-t",
                "new",
                "-x",
                "45"
            ]
        },
    ]
}
```

### FAQ

1. Decrypting works only partially. My files are present in the output folder, but they contain garbage

The .pk password was correct, but most probably the files weren't properly decoded. Table or XOR key is not correct; see [Decrypt and recover XOR key](#decrypt-and-recover-xor-key)
