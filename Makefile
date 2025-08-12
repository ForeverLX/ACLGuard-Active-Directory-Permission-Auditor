# Makefile - ACLGuard

CC = gcc
CFLAGS = -Wall -Wextra -Isrc -finput-charset=UTF-8 -fexec-charset=UTF-8
LDFLAGS = -lldap -llber

SRC = $(wildcard src/*.c) src/config.o src/errror_handler.o src/ldap.o src/aclguard.o \
	src/export.o src/main.o src/mock_ad.o src/risk_engine.o src/security.o 
OBJ = $(SRC:.c=.o)

TEST_SRC = tests/mock_validation.c
TEST_OBJ = $(TEST_SRC:.c=.o)

# Default target
all: ACLGuard

ACLGuard: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build and run tests
test: $(OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o test_runner $^ $(LDFLAGS)
	./test_runner 

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TEST_OBJ) ACLGuard test_runner