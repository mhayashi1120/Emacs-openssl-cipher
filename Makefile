EMACS = emacs

check: compile
	$(EMACS) -q -batch -l openssl-cipher.el -l openssl-cipher-test.el \
		-f ert-run-tests-batch-and-exit
	$(EMACS) -q -batch -l openssl-cipher.elc -l openssl-cipher-test.el \
		-f ert-run-tests-batch-and-exit

compile:
	$(EMACS) -q -batch -L . -f batch-byte-compile \
		openssl-cipher.el

clean:
	rm -f openssl-cipher.elc
