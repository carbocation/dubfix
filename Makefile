CC = clang
CFLAGS = -O2 -std=c11 -Wall -Wextra -Werror
CPPFLAGS = -Isrc
LDLIBS = -framework IOKit -framework CoreFoundation
SOURCES = src/cli.c src/dubfix.c src/profile.c src/transport_macos.c
HEADERS = src/profile.h src/transport_macos.h

.PHONY: all test clean
all: build/dubfix

build/dubfix: $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $@ $(LDLIBS)

test:
	CC="$(CC)" python3 tests/run_tests.py

clean:
	rm -rf build
