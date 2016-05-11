FSTAR_HOME=/home/maker/dev/FStar
FSTAR=$(FSTAR_HOME)/bin/fstar.exe
FSTAR_OPTIONS=--universes --include $(FSTAR_HOME)/ulib

all:
	$(FSTAR) $(FSTAR_OPTIONS) json.fst primitives.fst

.PHONY: all
