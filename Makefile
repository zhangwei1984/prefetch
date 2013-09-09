PROGS=loop fusexmp_fh mcd
CFLAGS+=-Wall -g -DHAVE_MCD=1
all: $(PROGS)

loop: loop.c circ.c mcd.c
	$(CC) $(CFLAGS) -DDEBUG $^ -o $@ `pkg-config fuse --cflags --libs` -pthread -ldb

fusexmp_fh: fusexmp_fh.c
	$(CC) $(CFLAGS) $^ -o $@ `pkg-config fuse --cflags --libs` -pthread

mcd: mcd.c
	$(CC) $(CFLAGS) -DHAVE_MCD=1 -DBUILD_MCD_MAIN -o $@ $^ -L/usr/lib/x86_64-linux-gnu -lpthread -lz -lm -lrt -ldl

clean:
	$(RM) $(PROGS)

test:
	./loop mnt && ls -l mnt && cat mnt/loop

mount:
	./loop mnt

umount:
	fusermount -u mnt
