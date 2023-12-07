CFLAGS=-Wall -Wextra -fPIC -fno-inline -g
LDFLAGS=-lssh
OBJS=sshdump.o args.o pcap.o session.o in_channel.o out_channel.o

all: sshdump

sshdump: $(OBJS)
	gcc $(CFLAGS) -o $@ $+ $(LDFLAGS)

%.o: %.c
	gcc $(CFLAGS) -c $^ -o $@

clean:
	rm *~ *.o sshdump

