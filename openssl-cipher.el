;;; openssl-cipher.el --- Encrypt/Decrypt string with password by openssl.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data, convenience, files
;; URL: https://github.com/mhayashi1120/Emacs-openssl-cipher/raw/master/openssl-cipher.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.7.0

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

;;; Install:

;; Put this file into load-path'ed directory, and byte compile it if
;; desired. And put the following expression into your ~/.emacs.
;;
;;     (require 'openssl-cipher)

;;; Usage:

;; * To encode a well encoded string (High level API)
;; `openssl-cipher-encrypt-string' <-> `openssl-cipher-decrypt-string'
;;
;; * To encode a binary string (Low level API)
;; `openssl-cipher-encrypt-unibytes' <-> `openssl-cipher-decrypt-unibytes'

;;; Sample:

;; * To encrypt my secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;; (defvar my-secret nil)

;; (let ((raw-string "My Secret"))
;;   (setq my-secret (openssl-cipher-encrypt-string raw-string))
;;   (clear-string raw-string))

;; * To decrypt `my-secret'

;; (openssl-cipher-decrypt-string my-secret)

;;; TODO:

;; * retry password when failed to decrypt.

;;; Code:

(defgroup openssl-cipher nil
  "Emacs openssl cipher interface."
  :group 'applications
  :prefix "openssl-cipher-")

(defvar quit-flag)

(defcustom openssl-cipher-algorithm "aes-256-cbc"
  "Cipher algorithm to encrypt a message."
  :group 'openssl-cipher
  :type 'string)

(defcustom openssl-cipher-command "openssl"
  "Openssl command name."
  :group 'openssl-cipher
  :type 'file)

(defvar openssl-cipher-string-encoding (terminal-coding-system))

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

(defun openssl-cipher--call/io-file (input function)
  (let ((time (nth 5 (file-attributes input))))
    (let ((output (openssl-cipher--create-temp-file)))
      (condition-case err
          (progn
            (funcall function input output)
            (openssl-cipher--purge-temp input)
            (rename-file output input)
            (set-file-times input time))
        (error
         (ignore-errors (openssl-cipher--purge-temp output))
         (signal (car err) (cdr err)))))))

(defun openssl-cipher--purge-temp (file)
  (let (delete-by-moving-to-trash)
    (delete-file file)))

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
   (let ((code (apply 'call-process openssl-cipher-command nil t nil args)))
     (when pass
       (clear-string pass))
     (unless (= (buffer-size) 0)
       (goto-char (point-min))
       (error "Openssl: %s" (buffer-substring-no-properties (point-min) (point-at-eol))))
     code)))

(defvar openssl-cipher-password nil)
(defun openssl-cipher--read-passwd (&optional confirm)
  ;;TODO concat new string for clear-string?
  (or openssl-cipher-password
      (read-passwd "Password: " confirm)))

(defun openssl-cipher-supported-types ()
  (openssl-cipher--with-env
   ;; this return non-zero value with succeeded
   (call-process openssl-cipher-command nil t nil "enc" "help")
   (goto-char (point-min))
   (unless (re-search-forward "^Cipher Types" nil t)
     (error "Unable parse supported types"))
   (let* ((text (buffer-substring (point) (point-max)))
          (args (split-string text "[ \t\n]" t))
          (algos (mapcar (lambda (a)
                           (and (string-match "\\`-\\(.*\\)" a)
                                (match-string 1 a))) args)))
     (delq nil algos))))

(defun openssl-cipher--check-save-file (file)
  (unless (or (null file)
              (and (file-exists-p file)
                   (y-or-n-p (format "Overwrite %s? " file))))
    ;;FIXME: should be user-error
    (signal 'quit nil)))

(defun openssl-cipher--encrypt-file (password input output algorithm encrypt-p &rest args)
  (apply
   'openssl-cipher--invoke
   password
   "enc"
   (concat "-" (or algorithm openssl-cipher-algorithm))
   (if encrypt-p "-e" "-d")
   "-in" input
   "-out" output
   args))

(defun openssl-cipher--call/string (input algorithm encrypt-p &optional pass &rest args)
  (let ((out (openssl-cipher--create-temp-file)))
    (unwind-protect
        (let ((in (openssl-cipher--create-temp-binary input)))
          (unwind-protect
              (let ((code (apply 'openssl-cipher--encrypt-file
                                 pass in out algorithm encrypt-p args)))
                (unless (= code 0)
                  (error "Command failed exit"))
                (openssl-cipher--file-unibytes out))
            (openssl-cipher--purge-temp in)))
      (openssl-cipher--purge-temp out))))

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
         (string-match "\\`[0-9a-fA-F][0-9a-fA-F]+\\'" input))
    input)
   ((and (stringp input)
         (not (multibyte-string-p input)))
    (mapconcat (lambda (x) (format "%02x" x)) input ""))
   ((eq input nil)
    "")
   (t
    (error "Not supported unibytes format"))))

;;;
;;; User interface
;;;

;;;###autoload
(defun openssl-cipher-encrypt-unibytes (unibyte-string &optional algorithm)
  "Encrypt a UNIBYTE-STRING to encrypted object which can be decrypted by
`openssl-cipher-decrypt-unibytes'"
  (when (multibyte-string-p unibyte-string)
    (error "Multibyte string is not supported"))
  (let ((pass (openssl-cipher--read-passwd t)))
    (openssl-cipher--call/string unibyte-string algorithm t pass)))

;;;###autoload
(defun openssl-cipher-decrypt-unibytes (encrypted-string &optional algorithm)
  "Decrypt a ENCRYPTED-STRING which was encrypted by
`openssl-cipher-encrypt-unibytes'"
  (unless (stringp encrypted-string)
    (error "Not a encrypted string"))
  (let ((pass (openssl-cipher--read-passwd)))
    (openssl-cipher--call/string encrypted-string algorithm nil pass)))

;;;###autoload
(defun openssl-cipher-encrypt-string (string &optional coding-system algorithm)
  "Encrypt a well encoded STRING to encrypted object which can be decrypted by
 `openssl-cipher-decrypt-string'.
TODO"
  (openssl-cipher-encrypt-unibytes
   (encode-coding-string
    string (or coding-system openssl-cipher-string-encoding))
   algorithm))

;;;###autoload
(defun openssl-cipher-decrypt-string (encrypted &optional coding-system algorithm)
  "Decrypt a ENCRYPTED object which was encrypted by
`openssl-cipher-encrypt-string'
TODO"
  (decode-coding-string
   (openssl-cipher-decrypt-unibytes encrypted algorithm)
   (or coding-system openssl-cipher-string-encoding)))

;;TODO not yet tested save-file
;;;###autoload
(defun openssl-cipher-encrypt-file (file &optional algorithm save-file)
  "Encrypt a FILE which can be decrypted by `openssl-cipher-decrypt-file'
TODO
todo about mtime keeping mtime"
  (openssl-cipher--check-save-file save-file)
  (let ((pass (openssl-cipher--read-passwd t)))
    (openssl-cipher--call/io-file
     file
     (lambda (input output)
       (openssl-cipher--encrypt-file pass input output algorithm t))))
  ;;TODO keep FILE?
  (when save-file
    (rename-file file save-file t)))

;;;###autoload
(defun openssl-cipher-decrypt-file (file &optional algorithm save-file)
  "Decrypt a FILE which was encrypted by `openssl-cipher-encrypt-file'
TODO
todo about mtime keeping mtime"
  (openssl-cipher--check-save-file save-file)
  (let ((pass (openssl-cipher--read-passwd)))
    (openssl-cipher--call/io-file
     file
     (lambda (input output)
       (openssl-cipher--encrypt-file pass input output algorithm nil))))
  ;;TODO keep FILE?
  (when save-file
    (rename-file file save-file t)))

;;TODO
;;;###autoload
(defun openssl-cipher-encrypt (unibyte-string key-input &optional iv-input algorithm)
  "Encrypt a UNIBYTE-STRING to encrypted object which can be decrypted by
`openssl-cipher-decrypt-unibytes'"
  (when (multibyte-string-p unibyte-string)
    (error "Multibyte string is not supported"))
  (let ((key (openssl-cipher--validate-input-bytes key-input))
        (iv (openssl-cipher--validate-input-bytes iv-input)))
    (apply 'openssl-cipher--call/string
           unibyte-string algorithm t nil
           `(
             "-K" ,key
             "-iv" ,iv))))

;;TODO
;;;###autoload
(defun openssl-cipher-decrypt (encrypted-string key-input &optional iv-input algorithm)
  "Decrypt a ENCRYPTED-STRING which was encrypted by
`openssl-cipher-encrypt-unibytes'"
  (unless (stringp encrypted-string)
    (error "Not a encrypted string"))
  (let ((key (openssl-cipher--validate-input-bytes key-input))
        (iv (openssl-cipher--validate-input-bytes iv-input)))
    (apply 'openssl-cipher--call/string
           encrypted-string algorithm nil nil
           `(
             "-K" ,key
             "-iv" ,iv))))

;;;###autoload
(defun openssl-cipher-installed-p ()
  "Return non-nil if `openssl-cipher' is correctly setup."
  (and (stringp openssl-cipher-command)
       (executable-find openssl-cipher-command)))

(provide 'openssl-cipher)

;;; openssl-cipher.el ends here
