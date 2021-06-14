CC = gcc
CFLAGS = -g -Wall -O2

TARGET = sha256

all: $(TARGET)

run: $(TARGET)
	cat sample.in | ./$(TARGET).o

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET).o $(TARGET).c

clean:
	$(RM) $(TARGET).o