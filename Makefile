include $(GOROOT)/src/Make.$(GOARCH)

TARG=ident
GOFILES=\
	ident.go\

include $(GOROOT)/src/Make.pkg

