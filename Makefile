OBJS=mmap.o xeq.o ldt.o timing xeq ldt
CFLAGS=-Wall -Werror

all: timing xeq ldt
ldt: mmap.o

clean:
	rm -f $(OBJS)
