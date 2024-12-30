# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

# Output executable name
TARGET = feistel_glochon

# Source files
SRCS = feistel_glochon.c

# Object files (generated from source files)
OBJS = $(SRCS:.c=.o)

# Default target: build the executable
all: $(TARGET)

# Rule to build the target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Rule to build object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean