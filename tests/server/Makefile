CC	= gcc
CFLAGS	= -g -Wall

.PHONY: all clean

TARGET = sws
OBJS= sws.o getpart.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	-rm -f $(OBJS) *~ $(TARGET) core logfile

