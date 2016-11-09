WIN32CC = i686-w64-mingw32-gcc
WIN64CC = x86_64-w64-mingw32-gcc
CC = gcc
CFLAGS += -std=c99 -shared

all: nhash32.dll nhash64.dll libnhash-linux-x86-64.so libnhash-linux-x86-32.so

nhash32.dll: nhash.c
	$(WIN32CC) $(CFLAGS) -o nhash32.dll nhash.c

nhash64.dll: nhash.c
	$(WIN64CC) $(CFLAGS) -o nhash64.dll nhash.c

libnhash-linux-x86-64.so: nhash.c
	$(CC) $(CFLAGS) -m64 -fPIC -o libnhash-linux-x86-64.so nhash.c
    
libnhash-linux-x86-32.so: nhash.c
	$(CC) $(CFLAGS) -m32 -fPIC -o libnhash-linux-x86-32.so nhash.c

clean:
	$(RM) *.so *.dll *.o