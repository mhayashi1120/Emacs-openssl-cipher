;;; openssl-cipher.el --- Encrypt/Decrypt string with password by openssl command.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: openssl encrypt decrypt password
;; URL: http://github.com/mhayashi1120/Emacs-openssl-cipher/raw/master/openssl-cipher.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.5.0

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

;; * encrypt file? `openssl-cipher-encrypt-file' <-> `openssl-cipher-decrypt-file'
;; * encrypt buffer? `openssl-cipher-encrypt-buffer' <-> `openssl-cipher-decrypt-buffer'
;; * encrypt region? `openssl-cipher-encrypt-region' <-> `openssl-cipher-decrypt-region'
;; * retry when failed to decrypt.

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

(defun openssl-cipher-encrypt-string (string)
  (openssl-cipher-encrypt-unibytes 
   (encode-coding-string string openssl-cipher-string-encoding)))

(defun openssl-cipher-decrypt-string (encrypted)
  (decode-coding-string
   (openssl-cipher-decrypt-unibytes encrypted) openssl-cipher-string-encoding))

(defun openssl-cipher-encrypt-unibytes (string)
  (when (multibyte-string-p string)
    (error "Multibyte string is not supported"))
  (let ((in (openssl-cipher--create-temp-file)))
    (unwind-protect
        (let ((out (openssl-cipher--create-temp-file)))
          (unwind-protect
              (progn
                (let ((coding-system-for-write 'binary))
                  (write-region string nil in nil 'no-msg))
                (with-temp-buffer
                  (let* ((proc (openssl-cipher--start-openssl 
                                openssl-cipher-algorithm
                                "-e"
                                "-in" in 
                                "-out" out
                                "-pass" "stdin")))
                    (openssl-cipher--send-password-and-wait proc t)
                    (unless (= (process-exit-status proc) 0)
                      (error "Failed encrypt"))))
                (with-temp-buffer
                  (set-buffer-multibyte nil)
                  (let ((coding-system-for-read 'binary))
                    (insert-file-contents out))
                  (openssl-cipher--create-encrypted 
                   openssl-cipher-algorithm (buffer-string))))
            (delete-file out)))
      (delete-file in))))

(defun openssl-cipher-decrypt-unibytes (encrypted)
  (unless (vectorp encrypted)
    (error "Not a encrypted object"))
  (let* ((algorithm (aref encrypted 0))
         (string (symbol-value algorithm)))
    (let ((in (openssl-cipher--create-temp-file)))
      (unwind-protect
          (progn
            (let ((coding-system-for-write 'binary))
              (write-region string nil in nil 'no-msg))
            (with-temp-buffer
              (let* ((proc (openssl-cipher--start-openssl 
                            (symbol-name algorithm)
                            "-d"
                            "-in" in 
                            "-pass" "stdin")))
                (openssl-cipher--send-password-and-wait proc nil)
                (unless (= (process-exit-status proc) 0)
                  (error "Bad decrypt")))
              (string-make-unibyte (buffer-string))))
        (delete-file in)))))

(defun openssl-cipher-supported-types ()
  (when (executable-find openssl-cipher-command)
    (with-temp-buffer
      (when (= (call-process openssl-cipher-command nil (current-buffer) nil
                             "--help") 0)
        (goto-char (point-min))
        (when (re-search-forward "^Cipher commands " nil t)
          (let ((start (line-beginning-position 2))
                (end (or (re-search-forward "^$" nil t) (point-max))))
            (split-string (buffer-substring start end) "[ \t\n]" t)))))))

;;
;; inner functions
;;

(defun openssl-cipher--create-temp-file ()
  (let ((file (make-temp-file "openssl-cipher-")))
    (set-file-modes file ?\600)
    file))

(defun openssl-cipher--start-openssl (&rest args)
  (set-buffer-multibyte nil)
  (let* ((coding-system-for-read 'binary)
         (coding-system-for-write 'binary)
         (proc (apply 'start-process "Openssl Cipher" (current-buffer)
                      openssl-cipher-command 
                      args)))
    (set-process-sentinel proc (lambda (p e)))
    proc))

(defun openssl-cipher--send-password-and-wait (proc encrypt-p)
  (unwind-protect
      (let* ((inhibit-quit t)
             (pass (read-passwd "Password: " encrypt-p)))
        (process-send-string proc (concat pass "\n"))
        (when pass
          (clear-string pass))
        (while (and (eq (process-status proc) 'run)
                    (not quit-flag))
          (sit-for 0.1)))
    (delete-process proc)))

(defun openssl-cipher--create-encrypted (algorithm string)
  (let ((vec (make-vector 1 nil)))
    (set (intern algorithm vec) string)
    vec))

(provide 'openssl-cipher)

;;; openssl-cipher.el ends here
