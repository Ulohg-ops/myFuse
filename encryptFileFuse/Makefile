# 編譯器選項，添加 FUSE 和 OpenSSL 的標誌
CFLAGS = -Wall -D_FILE_OFFSET_BITS=64 `pkg-config fuse --cflags` -I/usr/include/openssl

# 鏈接器選項，添加 FUSE 和 OpenSSL 的庫
LIBS = `pkg-config fuse --libs` -lssl -lcrypto

# 目標執行檔名稱
all: fuse_in_memory_fs

fuse_in_memory_fs: main.o
	gcc $(CFLAGS) -o fuse_in_memory_fs main.o $(LIBS)

main.o: main.c
	gcc $(CFLAGS) -c main.c

clean:
	rm -f *.o fuse_in_memory_fs