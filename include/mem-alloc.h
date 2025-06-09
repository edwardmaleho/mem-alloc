#ifndef _MEM_ALLLOC_
#define _MEM_ALLOC_

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>

#define PREV_INUSE 0x01
#define MIN_SIZE 0xFF

#define MIN_CHUNK_BODY_SIZE 32
#define CHUNK_HEADER_SIZE sizeof(meta_data)
#define MIN_FREE_CHUNK_TOTAL_SIZE (MIN_CHUNK_BODY_SIZE + CHUNK_HEADER_SIZE)

#define MAPSIZE (4096 * 2)

extern pthread_mutex_t alloc_lock;

typedef struct {
    size_t prev_size;
    size_t size;
} meta_data;

typedef struct free_chunk {
    meta_data meta_data;
    struct free_chunk* fd;
    struct free_chunk* bk;
 } free_chunk;

extern void* map_start;
extern void* map_end;

extern free_chunk* free_head;

meta_data* get_next_chunk(meta_data* meta);

meta_data* get_prev_chunk(meta_data* meta);

void remove_free(free_chunk* chunk);

void add_chunk_to_free_list(free_chunk* chunk);

void init_map(size_t map_size);

void new_free_head(free_chunk* new_head);

void* mem_malloc(size_t size);

void mem_free(void* ptr);

#endif // _MEM_ALLOC