CFLAGS=-Wall -Wextra -fPIC -fno-inline -g
LDFLAGS=-Wall -Wextra -lssh -lutil
OBJS=sshdump.o args.o pcap.o session.o in_channel.o out_channel.o

all: sshdump

sshdump: $(OBJS)
	gcc $(LDFLAGS) -o $@ $+

%.o: %.c
	gcc $(CFLAGS) -c $^ -o $@

clean:
	rm *~ *.o sshdump

