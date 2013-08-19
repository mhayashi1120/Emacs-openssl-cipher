(require 'ert)

(ert-deftest openssl-cipher-normal ()
  "Normal test (for ascii)"
  :tags '(openssl-cipher)
  ;; ascii as unibyte array
  (let ((E (let ((openssl-cipher-password "pass"))
             (prog1
                 (openssl-cipher-encrypt-unibytes "abcd")
               ;; check password is cleared.
               (should (equal openssl-cipher-password (make-string 4 0)))))))
    ;; check invalid pass
    (should-error (let ((openssl-cipher-password "not pass"))
                    (openssl-cipher-decrypt-string E)))
    (should (equal (let ((openssl-cipher-password "pass"))
                     (openssl-cipher-decrypt-unibytes E)) "abcd")))
  ;; ascii as unibyte string
  (let ((E (let ((openssl-cipher-password "pass"))
             (openssl-cipher-encrypt-string "abcd"))))
    (should (equal (let ((openssl-cipher-password "pass"))
                     (openssl-cipher-decrypt-string E)) "abcd"))))

(ert-deftest openssl-cipher-normal-multibyte ()
  "Normal test (for multibyte string)"
  :tags '(openssl-cipher)
  ;; check binary string
  (let ((E (let ((openssl-cipher-password "pass"))
             (openssl-cipher-encrypt-unibytes "\316\323"))))
    (should (equal (let ((openssl-cipher-password "pass"))
                     (openssl-cipher-decrypt-unibytes E)) "\316\323")))
  (let ((E (let ((openssl-cipher-password "pass"))
             (openssl-cipher-encrypt-string "test マルチバイト文字"))))
    (should (equal (let ((openssl-cipher-password "pass"))
                     (openssl-cipher-decrypt-string E)) "test マルチバイト文字"))))

(ert-deftest openssl-cipher-with-algorithm ()
  ""
  :tags '(openssl-cipher)
  (dolist (a '("aes-256-ecb" "aes-256-cbc" "aes-256-ctr"
               "aes-256-ofb" "aes-256-cfb" "aes-256-cfb1"
               "aes-256-cfb8"
               ;; seems not work
               ;; "aes-256-gcm"
               ))
    (let ((func (lambda (value key iv algo)
                  (should (equal value
                                 (openssl-cipher-decrypt
                                  (openssl-cipher-encrypt value key iv algo)
                                  key iv algo))))))
      (funcall func "a" [255] [0] a)
      (funcall func "a" "a" "a" a)
      (funcall func "a" "00" "a" a))))


(ert-deftest openssl-cipher-file ()
  ""
  :tags '(openssl-cipher)
  (let ((file (openssl-cipher--create-temp-binary "abcdefg")))
    (unwind-protect
        (progn
          (let ((mtime (nth 5 (file-attributes file)))
                (openssl-cipher-password (copy-sequence "a")))
            (openssl-cipher-encrypt-file file)
            (should (equal (nth 5 (file-attributes file)) mtime)))
          ;; wrong password
          (let ((openssl-cipher-password (copy-sequence "d")))
            (should-error (openssl-cipher-decrypt-file file)))
          (let ((openssl-cipher-password (copy-sequence "a")))
            (openssl-cipher-decrypt-file file))
          (should (equal (openssl-cipher--file-unibytes file) "abcdefg")))
      (delete-file file))))

(ert-deftest openssl-cipher-file-with-save-file ()
  ""
  :tags '(openssl-cipher)
  (let* ((file (openssl-cipher--create-temp-binary "opqrstu"))
         (save-file (concat file ".save-file"))
         (restore-file (concat file ".restore-file")))
    (unwind-protect
        (progn
          (let ((mtime (nth 5 (file-attributes file)))
                (openssl-cipher-password (copy-sequence "a")))
            (openssl-cipher-encrypt-file file nil save-file)
            (should (equal (nth 5 (file-attributes save-file)) mtime)))
          ;; wrong password
          (let ((openssl-cipher-password (copy-sequence "d")))
            (should-error (openssl-cipher-decrypt-file save-file nil restore-file)))
          (let ((openssl-cipher-password (copy-sequence "a")))
            (openssl-cipher-decrypt-file save-file nil restore-file))
          (should (equal (openssl-cipher--file-unibytes file)
                         (openssl-cipher--file-unibytes restore-file))))
      (openssl-cipher--purge-file file)
      (openssl-cipher--purge-file save-file)
      (openssl-cipher--purge-file restore-file)
      )))

