EXE=
WALL=-Wall

BINARIES=hmmverify$(EXE) hmmprint$(EXE) hmmextract$(EXE)

default: $(BINARIES) check doc

hmmTest$(EXE) $(BINARIES): *.hs
	ghc ${WALL} -Werror -O -o hmmTest --make HmmTest
	ghc ${WALL} -Werror -O -o hmmverify --make HmmVerify
	ghc ${WALL} -Werror -O -o hmmprint --make HmmPrint
	ghc ${WALL} -Werror -O -o hmmextract --make HmmExtract

hghtest$(EXE): *.lhs
	ghc ${WALL} -Werror -O -o hghtest --make HghTest

doc: HghCore.xhtml

distclean:
	# throw away everything that is not for publication
	rm -f *.o *.hi
	rm -f hmmTest$(EXE) $(BINARIES)
	rm -f hghtest$(EXE)
	rm -f *.was.run

clean: distclean
	# throw away all derived objects
	rm -f .htaccess
	rm -f *.xhtml

check: hmmTest.was.run hghtest.was.run doc

hmmTest.was.run: ./hmmTest$(EXE)
	rm -f hmmTest.was.run
	./hmmTest$(EXE)
	touch hmmTest.was.run

hghtest.was.run: ./hghtest$(EXE)
	rm -f hghtest.was.run
	./hghtest$(EXE)
	touch hghtest.was.run

sitecopy: distclean sitecopy-is-safe doc
	echo "Options +Indexes" > .htaccess
	sitecopy -u hmm-repo

sitecopy-is-safe:
	if [[ "${PWD}" != "${HOME}/projects/hmm" ]]; then false; fi
	@test "$$(darcs whatsnew --look-for-adds 2>&1)" = 'No changes!' \
		|| (echo "You have unrecorded changes!" && false)

%.xhtml: %.lhs
	rst2html.py --exit-status=info --report=info --source-link --generator --date --time $< $@ \
		|| (rm -f $@ && false)

