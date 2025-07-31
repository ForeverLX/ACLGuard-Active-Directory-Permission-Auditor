CC = gcc
CFLAGS = -Wall -g -Isrc -Iinclude -I/usr/include
LDFLAGS = -lldap -llber -ljson-c

OBJS = src/main.o src/config.o src/ldap.o src/risk_engine.o src/export.o src/error_handler.o

all: aclguard

aclguard: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f aclguard test $(OBJS)