CC	= gcc
OPTIM	= -O2
DEF	= -DDEFAULT_PORT=7676
CFLAGS	= -g -Wall $(OPTIM) $(DEF)

.PHONY: all clean

TARGET = sws
OBJS= sws.o getpart.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	-rm -f $(OBJS) *~ $(TARGET) core logfile

