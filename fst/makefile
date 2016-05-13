FSTAR_HOME=/home/maker/dev/FStar
FSTAR=$(FSTAR_HOME)/bin/fstar.exe
FSTAR_OPTIONS=--universes --include $(FSTAR_HOME)/ulib

ML=json.fst primitives.fst b64u.fst
FST=jwk.fst

all:
	$(FSTAR) $(FSTAR_OPTIONS) $(ML) $(FST)

.PHONY: all
