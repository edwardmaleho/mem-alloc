# mem-alloc
This project implements a basic memory allocator in C, simulating how malloc and free work internally. It manages dynamic memory by maintaining a free list and embedding metadata within memory chunks.

## Features
- Custom implementation of malloc, free (replacing standard malloc/free).
- Memory chunks contain metadata with size and flags.
- Free chunks store fd (forward) and bk (backward) pointers to maintain a doubly linked free list.
- Coalescing of adjacent free chunks when possible.
- Allocation uses alignment (e.g. 8- or 16-byte).
- Memory is initially acquired using mmap().

## Memory Chunk Structure
Allocated and free chunks share a common metadata layout at the beginning of the memory region. The basic layout:
```bash
[ prev_size , size | flags ] [ user data ] 
```
For the free chunk, the data area is used to store: 
```bash
[ fd ] [ bk ]
```

## Allocation Process
On malloc(size), the allocator:
- Rounds up size to maintain alignment.
- Searches the free list for a fitting chunk.
- If none is found, extends memory with mmap().

On free(ptr), the allocator:
- Converts ptr to the base of the chunk.
- Marks it as free (by clearing flags).
- Adds it to the free list.
- Coalesces with neighboring free chunks if applicable.

## Design Notes
- Metadata is embedded directly before the returned pointer.
- The free list is a global doubly linked list.
- Only free chunks store fd and bk. Allocated chunks do not.
- Each chunk’s size field includes flag bits (e.g., to track if the previous chunk is in use).

## Building and Running
### Build the project:
Enter the project root directory and run:
```bash
make
```

### Run the project:
After a successful build, execute the test program:
```bash
./build/mem-alloc
```
Use the provided mem_alloc() and mem_free() in place of standard malloc/free.
