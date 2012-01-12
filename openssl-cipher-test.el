(require 'ert)

(ert-deftest openssl-cipher-normal ()
  "Normal test (for ascii)"
  :tags '(openssl-cipher)
  (flet ((read-passwd (&rest dummy) (copy-sequence "pass")))
    ;; ascii as unibyte array
    (let ((enc (openssl-cipher-encrypt-unibytes "abcd")))
      (should (equal (openssl-cipher-decrypt-unibytes enc) "abcd")))
    ;; ascii as unibyte string
    (let ((enc (openssl-cipher-encrypt-string "abcd")))
      (should (equal (openssl-cipher-decrypt-string enc) "abcd")))))

(ert-deftest openssl-cipher-normal-multibyte ()
  "Normal test (for multibyte string)"
  :tags '(openssl-cipher)
  (flet ((read-passwd (&rest dummy) (copy-sequence "pass")))
    ;; check binary string
    (let ((enc (openssl-cipher-encrypt-unibytes "\316\323")))
      (should (equal (openssl-cipher-decrypt-unibytes enc) "\316\323")))
    (let ((enc (openssl-cipher-encrypt-string "test マルチバイト文字")))
      (should (equal (openssl-cipher-decrypt-string enc) "test マルチバイト文字")))))

(ert-deftest openssl-cipher-invalid-password ()
  "Invalid password."
  :tags '(openssl-cipher)
  (lexical-let ((passes `("pass" "invaild")))
    (flet ((read-passwd (&rest dummy) (pop passes)))
      (let ((enc (openssl-cipher-encrypt-string "test string")))
        (should-error (openssl-cipher-decrypt-string enc))))))

