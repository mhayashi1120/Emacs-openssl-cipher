openssl-cipher.el
=================

`openssl-cipher` is a library to encrypt/decrypt string or file with
`openssl` command.

## Install:

1. Install `openssl` command to your system by
 apt, yum... whatever you desire.

 Source code: http://www.openssl.org/source/

2. Put this file into load-path'ed directory, and byte compile it
 if desired. And put the following expression into your ~/.emacs.

      (require 'openssl-cipher)

## Usage:

* To encrypt a well encoded string (High level API)

 `openssl-cipher-encrypt-string` <-> `openssl-cipher-decrypt-string`

* To encrypt a binary string (Middle level API)

 `openssl-cipher-encrypt-unibytes` <-> `openssl-cipher-decrypt-unibytes`

* To encrypt a binary string (Low level API)

 `openssl-cipher-encrypt` <-> `openssl-cipher-decrypt`

* To encrypt a file

 `openssl-cipher-encrypt-file` <-> `openssl-cipher-decrypt-file`

## Sample:

* To encrypt my secret
 Please ensure that do not forget `clear-string` you want to hide.

      (defvar my-secret nil)

      (let ((raw-string "My Secret"))
        (setq my-secret (openssl-cipher-encrypt-string raw-string))
        (clear-string raw-string))

* To decrypt `my-secret`

        (openssl-cipher-decrypt-string my-secret)
