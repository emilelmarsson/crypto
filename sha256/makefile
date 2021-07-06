CC = gcc
CFLAGS = -g -Wall -O2

TARGET = sha256

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET).out $(TARGET).c

clean:
	$(RM) $(TARGET).o