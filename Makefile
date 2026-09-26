# Makefile for kerbrute BOF
# Requires mingw-w64: apt install gcc-mingw-w64-x86-64-posix

CC64 = x86_64-w64-mingw32-gcc
CC32 = i686-w64-mingw32-gcc
CFLAGS = -masm=intel -Wall -Wno-unused-variable -Wno-unused-function -Wno-misleading-indentation -fno-stack-check

all: kerbrute.x64.o kerbrute.x86.o

kerbrute.x64.o: kerbrute.c
	$(CC64) $(CFLAGS) -o $@ -c $<

kerbrute.x86.o: kerbrute.c
	$(CC32) $(CFLAGS) -o $@ -c $<

clean:
	rm -f kerbrute.x64.o kerbrute.x86.o
