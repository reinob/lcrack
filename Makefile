# auto-generated Makefile, please adjust if needed

CC=arm-none-eabi-gcc
CFLAGS=-O3 -D/usr/include/arm-linux-gnueabi/
LDFLAGS=

MAIN_BIN = lcrack
MAIN_HDR = xtn_def.h xtn_method.h global.h
MAIN_SRC = engine.c set.c key.c xtn_method.c md4.c md5.c base64.c sha1.c
MAIN_OBJ = engine.o set.o key.o xtn_method.o md4.o md5.o base64.o sha1.o

MKTBL_BIN = mktbl
MKTBL_HDR = xtn_def.h xtn_method.h global.h
MKTBL_SRC = mktbl.c xtn_method.c md4.c md5.c base64.c sha1.c
MKTBL_OBJ = mktbl.o xtn_method.o md4.o md5.o base64.o sha1.o

REGEX_BIN = regex
REGEX_HDR = global.h
REGEX_SRC = regex.c set.c
REGEX_OBJ = regex.o set.o

MKWORD_BIN = mkword
MKWORD_HDR = 
MKWORD_SRC = mkword.c
MKWORD_OBJ = mkword.o

XTN_HDR=mod_dom.h mod_md4.h mod_md5.h mod_nt4.h mod_null.h mod_sha1.h
XTN_SRC=mod_dom.c mod_md4.c mod_md5.c mod_nt4.c mod_null.c mod_sha1.c
XTN_OBJ=mod_dom.o mod_md4.o mod_md5.o mod_nt4.o mod_null.o mod_sha1.o

BIN_EXTRA=README COPYING CHANGES AUTHORS CREDITS charset.txt regex.txt
SRC_EXTRA=configure xtn_method.h.in xtn_method.c.in Makefile.in Makefile

# fixed Makefile part (not auto-generated)

all: $(MAIN_BIN) $(REGEX_BIN) $(MKWORD_BIN) $(MKTBL_BIN)

$(MAIN_BIN): $(MAIN_OBJ) $(XTN_OBJ)
	$(CC) -o $(MAIN_BIN) $(MAIN_OBJ) $(XTN_OBJ) $(LDFLAGS)

$(MKTBL_BIN): $(MKTBL_OBJ) $(XTN_OBJ)
	$(CC) -o $(MKTBL_BIN) $(MKTBL_OBJ) $(XTN_OBJ) $(LDFLAGS)

$(REGEX_BIN): $(REGEX_OBJ)
	$(CC) -o $(REGEX_BIN) $(REGEX_OBJ) $(LDFLAGS)

$(MKWORD_BIN): $(MKWORD_OBJ)
	$(CC) -o $(MKWORD_BIN) $(MKWORD_OBJ) $(LDFLAGS)

clean:
	rm -f $(MAIN_OBJ) $(MAIN_BIN) $(XTN_OBJ)
	rm -f $(MKTBL_OBJ) $(MKTBL_BIN)
	rm -f $(REGEX_OBJ) $(REGEX_BIN)
	rm -f $(MKWORD_OBJ) $(MKWORD_BIN)

distclean: clean
	rm -f Makefile xtn_method.h xtn_method.c
