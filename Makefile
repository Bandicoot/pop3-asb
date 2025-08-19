CFLAGS += -g -I/usr/local/include

pop3asb: pop3.o
	cc $(CFLAGS) -o pop3asb pop3.o -lcrypt -lmd -L/usr/local/lib -lgdbm

shar:
	shar pop3.c pop3.h Makefile

/usr/local/libexec/pop3asb: pop3asb
	cp pop3asb /usr/local/libexec

install: /usr/local/libexec/pop3asb
