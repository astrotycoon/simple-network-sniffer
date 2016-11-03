.PHONY: all clean

#CC:=arm-hisi-linux-gcc
CC:=gcc
#CFLAGS:=-Wall -g3 -ggdb
CFLAGS:=-Wall -O3 -fstrict-aliasing -Wstrict-aliasing=2
CFLAGS+=-I../include
CFLAGS+=-Wl,-rpath,/media/sdb1/LIBPCAP/test/lib
LDFLAGS:=-L../lib 
LDLIBS:=/media/sdb1/LIBPCAP/test/lib/libpcap.a

srcs:=msniffer.c
objsdir:=objdir
objs:=$(srcs:%.c=$(objsdir)/%.o)

exe:=msniffer

all: $(exe)

$(exe): $(objs)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(objs): | $(objsdir)
$(objsdir):
	@mkdir -p $@

$(objsdir)/%.o: %.c
	$(CC) $(CFLAGS) -E -o $@.i $<
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -rf $(exe) $(objsdir)
