;;; openssl-cipher.el --- Encrypt/Decrypt string with password by openssl -*- lexical-binding: t -*-

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data, convenience, files
;; URL: https://github.com/mhayashi1120/Emacs-openssl-cipher
;; Emacs: GNU Emacs 24 or later
;; Version: 0.8.1
;; Package-Requires: ((emacs "24") (cl-lib "0.7.1"))

;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation; either version 3, or (at
;; your option) any later version.

;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs; see the file COPYING.  If not, write to the
;; Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
;; Boston, MA 02110-1301, USA.

;;; Commentary:

;; `openssl-cipher` is a library to encrypt/decrypt string or file with
;; `openssl` command.

;; ## Install:

;; 1. Install `openssl` command to your system by
;;  apt, yum... whatever you desire.

;;  Source code: http://www.openssl.org/source/

;; 2. Put this file into load-path'ed directory, and byte compile it
;;  if desired. And put the following expression into your ~/.emacs.

;;       (require 'openssl-cipher)

;; ## Usage:

;; * To encrypt a well encoded string (High level API)

;;  `openssl-cipher-encrypt-string` <-> `openssl-cipher-decrypt-string`

;; * To encrypt a binary string (Middle level API)

;;  `openssl-cipher-encrypt-unibytes` <-> `openssl-cipher-decrypt-unibytes`

;; * To encrypt a binary string (Low level API)

;;  `openssl-cipher-encrypt` <-> `openssl-cipher-decrypt`

;; * To encrypt a file

;;  `openssl-cipher-encrypt-file` <-> `openssl-cipher-decrypt-file`

;; ## Sample:

;; * To encrypt my secret
;;  Please ensure that do not forget `clear-string` you want to hide.

;;       (defvar my-secret nil)

;;       (let ((raw-string "My Secret"))
;;         (setq my-secret (openssl-cipher-encrypt-string raw-string))
;;         (clear-string raw-string))

;; * To decrypt `my-secret`

;;         (openssl-cipher-decrypt-string my-secret)

;;; TODO:
;; * should not use temporary file? (man shred)

;;; Code:

(defgroup openssl-cipher nil
  "Emacs openssl cipher interface."
  :group 'applications
  :prefix "openssl-cipher-")

(defcustom openssl-cipher-algorithm "aes-256-cbc"
  "Default cipher algorithm to encrypt a message."
  :group 'openssl-cipher
  :type 'string)

(defcustom openssl-cipher-command "openssl"
  "Openssl command name."
  :group 'openssl-cipher
  :type 'file)

(defvar openssl-cipher-string-encoding (terminal-coding-system))

(defcustom openssl-cipher-encryption-version 'latest
  "Define this `openssl-cipher' package's default encryption behavior.

Supported values are:
`latest' : The most secure version `openssl' command recommended which this 
    package's maintainer detected. This is default value.
`default' : Completely default behavior of `openssl' command. No extra
     arguments when call `openssl' command. Current version of
     `openssl' (1.1.1n on 2023-02-16) this is same as `legacy-sha256' .
`pbkdf2' : Use key derivation as `PBKDF2' algorithm.
`legacy-sha256' : Already deprecated on `openssl'.
`legacy-md5' : Already deprecated on `openssl'. This is initial version
     of this package supported.
"
  :group 'openssl-cipher
  :type '(choice
          (const default)
          (const latest)
          (const pbkdf2)
          (const legacy-sha256)
          (const legacy-md5)))
  
;;;
;;; inner functions
;;;

(defun openssl-cipher--create-temp-binary (string)
  (let ((file (openssl-cipher--create-temp-file))
        (coding-system-for-write 'binary))
    (write-region string nil file nil 'no-msg)
    file))

(defun openssl-cipher--file-unibytes (file)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((coding-system-for-read 'binary))
      (insert-file-contents file))
    (buffer-string)))

(defun openssl-cipher--call-with-io-file (input output function)
  (let* ((in-file (expand-file-name input))
         (output-file (expand-file-name output))
         (mtime (nth 5 (file-attributes in-file)))
         (same-filep (equal in-file output-file))
         (out-file (or (and (not same-filep) output-file)
                       (openssl-cipher--create-temp-file))))
    (condition-case err
        (progn
          (funcall function out-file)
          (set-file-times out-file mtime)
          (when same-filep
            (openssl-cipher--purge-file in-file)
            (rename-file out-file in-file)))
      (error
       (openssl-cipher--purge-file out-file)
       (signal (car err) (cdr err))))))

(defun openssl-cipher--purge-file (file)
  (when (file-exists-p file)
    (let ((size (nth 7 (file-attributes file))))
      (let ((coding-system-for-write 'binary))
        (write-region (make-string size 0) nil file nil 'no-msg)))
    (let (delete-by-moving-to-trash)
      (delete-file file))))

(defun openssl-cipher--create-temp-file ()
  (let ((file (make-temp-file "openssl-cipher-")))
    (set-file-modes file ?\600)
    file))

(defmacro openssl-cipher--with-env (&rest form)
  (declare (debug t))
  `(with-temp-buffer
     (let ((process-environment (copy-sequence process-environment)))
       (setenv "LANG" "C")
       (let ((coding-system-for-read 'binary)
             (coding-system-for-write 'binary))
         ,@form))))

(defun openssl-cipher--invoke (&optional pass &rest args)
  (openssl-cipher--with-env
   (when pass
     ;; if encryption
     (setenv "EMACS_OPENSSL_CIPHER" pass)
     (setq args (append
                 args
                 (list "-pass" (format "env:%s" "EMACS_OPENSSL_CIPHER")))))
   (let ((code (apply #'call-process openssl-cipher-command nil t nil args)))
     (when pass
       (clear-string pass))
     (unless (= code 0)
       (goto-char (point-min))
       (let ((msg (buffer-substring-no-properties
                   (point-min) (line-end-position))))
         (error "Openssl: %s" msg)))
     code)))

(defvar openssl-cipher-password nil
  "To suppress the password prompt while Encryption/Decryption.
This is a hiding, volatile parameter. This variable contents will
be cleared after a Encryption/Decryption.")

(defun openssl-cipher--read-passwd (&optional confirm)
  (or (and (stringp openssl-cipher-password)
           openssl-cipher-password)
      (read-passwd "Password: " confirm)))

(defun openssl-cipher-supported-types ()
  (or (openssl-cipher--supported-types0002)
      (openssl-cipher--supported-types0001)
      (error "Unable parse supported ciphers")))

(defun openssl-cipher--supported-types0002 ()
  (openssl-cipher--with-env
   (when (equal (call-process
                 openssl-cipher-command nil t nil
                 "list" "-cipher-commands")
                0)
     (let* ((text (buffer-substring (point-min) (point-max)))
            (algos (split-string text "[ \t\n]" t)))
       (delq nil algos)))))

(defun openssl-cipher--supported-types0001 ()
  (openssl-cipher--with-env
   ;; this return non-zero value with succeeded
   (call-process openssl-cipher-command nil t nil "enc" "help")
   (goto-char (point-min))
   (when (re-search-forward "^Cipher Types" nil t)
     (let* ((text (buffer-substring (point) (point-max)))
            (args (split-string text "[ \t\n]" t))
            (algos (mapcar (lambda (a)
                             (and (string-match "\\`-\\(.*\\)" a)
                                  (match-string 1 a)))
                           args)))
       (delq nil algos)))))

(defun openssl-cipher--check-save-file (file)
  (unless (or (null file)
              (not (file-exists-p file))
              (y-or-n-p (format "Overwrite %s? " file)))
    ;;FIXME: should be user-error
    (signal 'quit nil)))

(defun openssl-cipher--encrypt-file (password in-file out-file
                                              algorithm encrypt-p properties
                                              &rest args)
  ;; Support misc arguents to resotre previous `openssl` encryption behavior. 
  ;; openssl-1.1.1n warn the default argument although.
  (cl-ecase (or (plist-get properties :version)
                openssl-cipher-encryption-version)
    ;; Current latest is same as `pbkdf2'
    ((latest)
     (setq args (append args (list "-pbkdf2"))))
    ((default))
    ((legacy-md5)
     (setq args (append args (list "-md" "md5"))))
    ((legacy-sha256)
     (setq args (append args (list "-md" "sha256"))))
    ((pbkdf2)
     (setq args (append args (list "-pbkdf2")))))

  (apply
   #'openssl-cipher--invoke
   password
   "enc"
   (concat "-" (or algorithm openssl-cipher-algorithm))
   (if encrypt-p "-e" "-d")
   "-in" in-file
   "-out" out-file
   args))

(defun openssl-cipher--call-with-string (input algorithm encrypt-p properties
                                               &optional pass
                                               &rest args)
  (let ((out (openssl-cipher--create-temp-file)))
    (unwind-protect
        (let ((in (openssl-cipher--create-temp-binary input)))
          (unwind-protect
              (progn
                (apply #'openssl-cipher--encrypt-file
                       pass in out algorithm encrypt-p properties args)
                (openssl-cipher--file-unibytes out))
            (openssl-cipher--purge-file in)))
      (openssl-cipher--purge-file out))))

(defun openssl-cipher--check-unibyte-vector (vector)
  (mapconcat
   (lambda (x)
     (unless (and (numberp x)(<= 0 x) (<= x 255))
       (error "Invalid unibyte vector"))
     (format "%02x" x))
   vector ""))

(defun openssl-cipher--validate-input-bytes (input)
  (cond
   ((vectorp input)
    (openssl-cipher--check-unibyte-vector input))
   ((and (stringp input)
         (string-match "\\`[0-9a-fA-F]\\{2,\\}\\'" input))
    input)
   ;; hex string and unibyte string is not exclusive,
   ;; but not need to concern about it almost case since
   ;; INPUT is key or iv randomized value.
   ((and (stringp input)
         (not (multibyte-string-p input)))
    (mapconcat (lambda (x) (format "%02x" x)) input ""))
   ((eq input nil)
    "")
   (t
    (error "Not supported unibytes format"))))

(defun openssl-cipher--check-byte-string (string)
  (unless (stringp string)
    (error "Not a byte string"))
  (when (multibyte-string-p string)
    (error "Multibyte string is not supported")))

;;;
;;; User interface
;;;

;;;###autoload
(defun openssl-cipher-encrypt-unibytes (unibyte-string &optional algorithm)
  "Encrypt a UNIBYTE-STRING to encrypted object which can be decrypted by
`openssl-cipher-decrypt-unibytes'"
  (openssl-cipher--check-byte-string unibyte-string)
  (let ((pass (openssl-cipher--read-passwd t)))
    (openssl-cipher--call-with-string unibyte-string algorithm t nil pass)))

;;;###autoload
(defun openssl-cipher-decrypt-unibytes (encrypted-string
                                        &optional algorithm
                                        &rest keywords)
  "Decrypt a ENCRYPTED-STRING which was encrypted by
`openssl-cipher-encrypt-unibytes'

Supported KEYWORDS:
  :version : Override `openssl-cipher-encryption-version' setting.
"
  (openssl-cipher--check-byte-string encrypted-string)
  (let ((pass (openssl-cipher--read-passwd)))
    (openssl-cipher--call-with-string
     encrypted-string algorithm nil keywords pass)))

;;;###autoload
(defun openssl-cipher-encrypt-string (string &optional coding-system algorithm)
  "Encrypt a well encoded STRING to encrypted object which can be decrypted by
 `openssl-cipher-decrypt-string'.
If ALGORITHM is ommited default value is `openssl-cipher-algorithm'."
  (openssl-cipher-encrypt-unibytes
   (encode-coding-string
    string (or coding-system openssl-cipher-string-encoding))
   algorithm))

;;;###autoload
(defun openssl-cipher-decrypt-string (encrypted
                                      &optional coding-system algorithm
                                      &rest keywords)
  "Decrypt a ENCRYPTED object which was encrypted by
`openssl-cipher-encrypt-string'
If ALGORITHM is ommited default value is `openssl-cipher-algorithm'.

KEYWORDS : Same as `openssl-cipher-decrypt-unibytes'
"
  (decode-coding-string
   (apply #'openssl-cipher-decrypt-unibytes encrypted algorithm keywords)
   (or coding-system openssl-cipher-string-encoding)))

;;;###autoload
(defun openssl-cipher-encrypt (unibyte-string key-input
                                              &optional iv-input algorithm)
  "Encrypt a UNIBYTE-STRING to encrypted object which can be decrypted by
`openssl-cipher-decrypt-unibytes' .
KEY-INPUT and IV-INPUT is passed with a correct format to -K and -iv.
 Above options accept unibyte string or hex format or vector which contain
 only byte. This may be shown in the command argument like ps command."
  (openssl-cipher--check-byte-string unibyte-string)
  (let ((key (openssl-cipher--validate-input-bytes key-input))
        (iv (openssl-cipher--validate-input-bytes iv-input)))
    (apply #'openssl-cipher--call-with-string
           unibyte-string algorithm t nil nil
           `(
             "-K" ,key
             "-iv" ,iv))))

;;;###autoload
(defun openssl-cipher-decrypt
    (encrypted-string key-input
                      &optional
                      iv-input algorithm
                      &rest keywords)
  "Decrypt a ENCRYPTED-STRING which was encrypted by
`openssl-cipher-encrypt-unibytes' .

See more information about KEY-INPUT and IV-INPUT `openssl-cipher-encrypt'

KEYWORDS : Same as `openssl-cipher-decrypt-unibytes'
"
  (openssl-cipher--check-byte-string encrypted-string)
  (let ((key (openssl-cipher--validate-input-bytes key-input))
        (iv (openssl-cipher--validate-input-bytes iv-input)))
    (apply #'openssl-cipher--call-with-string
           encrypted-string algorithm nil keywords nil
           `(
             "-K" ,key
             "-iv" ,iv))))

;;;###autoload
(defun openssl-cipher-encrypt-file (file &optional algorithm save-file)
  "Encrypt a FILE which can be decrypted by `openssl-cipher-decrypt-file'

If ALGORITHM is nil then use `openssl-cipher-algorithm' to encrypt.
SAVE-FILE is a new file name of encrypted file name.
 If this file already exists, confirm to overwrite by minibuffer prompt.
 Do not forget to delete FILE if you do not want plain file."
  (openssl-cipher--check-save-file save-file)
  (let ((pass (openssl-cipher--read-passwd t)))
    (openssl-cipher--call-with-io-file
     file (or save-file file)
     (lambda (output)
       (openssl-cipher--encrypt-file pass file output algorithm t nil)))))

;;;###autoload
(defun openssl-cipher-decrypt-file (file &optional algorithm save-file
                                         &rest keywords)
  "Decrypt a FILE which was encrypted by `openssl-cipher-encrypt-file'

If ALGORITHM is nil then use `openssl-cipher-algorithm' to decrypt.
SAVE-FILE is a new file name of decrypted file name.
 If this file already exists, confirm to overwrite by minibuffer prompt.
 Do not forget to delete FILE if you do not want encrypted file.

KEYWORDS : Same as `openssl-cipher-decrypt-unibytes'
"
  (openssl-cipher--check-save-file save-file)
  (let ((pass (openssl-cipher--read-passwd)))
    (openssl-cipher--call-with-io-file
     file (or save-file file)
     (lambda (output)
       (openssl-cipher--encrypt-file pass file output algorithm nil keywords)))))

;;;###autoload
(defun openssl-cipher-installed-p ()
  "Return non-nil if `openssl-cipher' is correctly setup."
  (and (stringp openssl-cipher-command)
       (executable-find openssl-cipher-command)))

(provide 'openssl-cipher)

;;; openssl-cipher.el ends here
