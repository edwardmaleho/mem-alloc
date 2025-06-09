CC = gcc

CFLAGS = -Wall -Wextra -pedantic -g -pthread -Iinclude

SRCDIR = src
TESTDIR = tests
INC_DIR = include

BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj

TARGET = $(BUILDDIR)/mem-alloc

MEM_ALLOC_SRC = $(SRCDIR)/mem-alloc.c
MAIN_SRC = $(TESTDIR)/main.c

MEM_ALLOC_OBJ = $(OBJDIR)/mem-alloc.o
MAIN_OBJ = $(OBJDIR)/main.o

OBJECTS = $(MEM_ALLOC_OBJ) $(MAIN_OBJ)

.PHONY: all clean run

all: $(TARGET)

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(TARGET): $(OBJECTS) $(BUILDDIR) $(OBJDIR)
	@echo "Linking $@"
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

$(MEM_ALLOC_OBJ): $(MEM_ALLOC_SRC) $(OBJDIR) $(INC_DIR)/mem-alloc.h
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(MAIN_OBJ): $(MAIN_SRC) $(OBJDIR) $(INC_DIR)/mem-alloc.h
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning up build artifacts..."
	@rm -rf $(BUILDDIR)

run: $(TARGET)
	@echo "Running $(TARGET)..."
	@./$(TARGET)