check:
	emacs -q -batch -eval "(byte-compile-file \"openssl-cipher.el\")"; \
	emacs -q -batch -l openssl-cipher.el -l openssl-cipher-test.el \
		-eval "(ert-run-tests-batch-and-exit '(tag openssl-cipher))"

clean:
	rm -f openssl-cipher.elc
