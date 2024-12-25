CFLAGS = -Wall -D_FILE_OFFSET_BITS=64
LIBS = -lfuse

all: fuse_in_memory_fs

fuse_in_memory_fs: main.o
	gcc $(CFLAGS) -o fuse_in_memory_fs main.o $(LIBS)

main.o: main.c
	gcc $(CFLAGS) -c main.c

clean:
	rm -f *.o fuse_in_memory_fs
