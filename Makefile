.NOTPARALLEL:

PKGNAME=sniffer
SRCS    = $(wildcard *.c)
OBJS    = $(patsubst %.c, %.o, $(SRCS))

CFLAGS += $(DEFS)
#CFLAGS = -Wall -g -I$(shell pwd)/include
CFLAGS = -g -I$(shell pwd)/include

#######################################################################################
%.d: %.c
	@echo "  [DEP]  $@"
	@$(CC) -MM $(CFLAGS) $< | sed -e 's,\($*\)\.o[ :]*,$(basename $@).o $@: ,g' > $@

%.o: %.c
	@echo "  [CC]   $@"
	@$(CC) $(CFLAGS) -c $< -o $@
########################################################################################

.PHONY: all clean

all: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PKGNAME) $^ $(LDLIBS)

clean:
	rm -rf $(OBJS) $(PKGNAME)
