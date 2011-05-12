(require 'el-mock)
(require 'el-expectations)

(expectations 
  ;; ascii as unibyte array
  (expect "abcd"
    (with-mock
      (stub read-passwd => (copy-sequence "pass"))
      (let ((enc (openssl-cipher-encrypt-unibytes "abcd")))
        (openssl-cipher-decrypt-unibytes enc))))

  ;; ascii as unibyte string
  (expect "abcd"
    (with-mock
      (stub read-passwd => (copy-sequence "pass"))
      (let ((enc (openssl-cipher-encrypt-string "abcd")))
        (openssl-cipher-decrypt-string enc))))

  ;; check binary string
  (expect "\316\323"
    (with-mock
      (stub read-passwd => (copy-sequence "pass"))
      (let ((enc (openssl-cipher-encrypt-unibytes "\316\323")))
        (openssl-cipher-decrypt-unibytes enc))))

  (expect "test マルチバイト文字"
    (with-mock
      (stub read-passwd => (copy-sequence "pass"))
      (let ((enc (openssl-cipher-encrypt-string "test マルチバイト文字")))
        (openssl-cipher-decrypt-string enc))))

  ;; invalid password.
  (expect (error)
    (with-mock
      (stub read-passwd => (lexical-let ((passes `("pass" "invaild"))) (pop passes)))
      (let ((enc (openssl-cipher-encrypt-string "test string")))
        (openssl-cipher-decrypt-string enc))))
  )

(expectations-execute)
