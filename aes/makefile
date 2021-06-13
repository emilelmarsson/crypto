CC = gcc
CFLAGS = -g -Wall -O2

TARGET = aes

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET).o $(TARGET).c

clean:
	$(RM) $(TARGET).o