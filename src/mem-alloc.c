#include "mem-alloc.h"

pthread_mutex_t alloc_lock = PTHREAD_MUTEX_INITIALIZER;

void* map_start = NULL;

void* map_end = NULL;

free_chunk* free_head;


meta_data* get_next_chunk(meta_data* meta) {
    if (!meta)
        return NULL;
    meta_data* next_chunk = (meta_data*)((char*)(meta+1) + (meta->size & ~0xF));

    if ((void*)next_chunk >= map_end)
        return NULL;
    if ((void*)(next_chunk + 1) > map_end)
        return NULL;

    return next_chunk;
}

meta_data* get_prev_chunk(meta_data* meta) {
    if (!meta || (void*)meta == map_start)
        return NULL;
    
    meta_data* prev_chunk = (meta_data*)((char*)meta - meta->prev_size - sizeof(meta_data));
    if ((void*)prev_chunk < map_start)
        return NULL;
    
    return prev_chunk;
}

void remove_free(free_chunk* chunk) {
    if (!chunk) return;
    printf("Chunk->fd: %p\n", chunk->fd);
    printf("Chunk->bk: %p\n", chunk->bk);

    if (chunk->bk) {
        chunk->bk->fd = chunk->fd;
    } else {
        free_head = chunk->fd;
    }
    if (chunk->fd) {
        chunk->fd->bk = chunk->bk;
    }
    chunk->fd = NULL;
    chunk->bk = NULL;
    printf("Removed: %p", chunk);
}

void add_chunk_to_free_list(free_chunk* chunk) {
    if (!chunk) return;

    chunk->fd = free_head;
    chunk->bk = NULL;
    if (free_head != NULL) {
        free_head->bk = chunk;
    }
    free_head = chunk;
}

void init_map(size_t map_size) {
    map_start = mmap(NULL, map_size + sizeof(meta_data), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_start == MAP_FAILED) {
        perror("Failed to create map");
        exit(EXIT_FAILURE);
    }
    map_end = (void*)((char*)map_start + map_size);

    free_head = (free_chunk*)map_start;
    free_head->meta_data.size = (map_size - CHUNK_HEADER_SIZE) | PREV_INUSE;
    free_head->meta_data.prev_size = 0;
    free_head->fd = NULL;
    free_head->bk = NULL;
    print_free_block(free_head);
}

void new_free_head(free_chunk* new_head) {
    free_head->bk = new_head;
    new_head->fd = free_head;
    new_head->bk = NULL;
    free_head = new_head;
}

void* mem_malloc(size_t size) {
    pthread_mutex_lock(&alloc_lock);
    printf("Malloc request for size:%u\n", size);
    if (size == 0) {
        pthread_mutex_unlock(&alloc_lock);
        return NULL;
    }
    if (map_start == NULL) {
        init_map(MAPSIZE);
    }
    size_t adjusted_size = (size + 0xF) & ~0xF;
    free_chunk* curr_free = free_head;
    free_chunk* best_fit = NULL;

    // First fit search
    while (curr_free != NULL) {
        size_t curr_size = curr_free->meta_data.size & ~0xF;
        if (curr_size >= adjusted_size + CHUNK_HEADER_SIZE) {
            best_fit = curr_free;
            break;
        }
        curr_free = curr_free->fd;
    }

    if (best_fit == NULL) {
        printf("Malloc: No suitable free block found.\n");
        pthread_mutex_unlock(&alloc_lock);
        return NULL;
    }
    
    meta_data* alloc_block = (meta_data*)best_fit;
    size_t free_chunk_size = best_fit->meta_data.size & ~0xF;
    size_t free_chunk_inuse = best_fit->meta_data.size & PREV_INUSE;

    remove_free(best_fit);

    size_t remaining_space = free_chunk_size - adjusted_size;

    // TODO: create different free list sizes and place the chunk in the specific free list
    if (remaining_space >= MIN_FREE_CHUNK_TOTAL_SIZE) {
        alloc_block->size = adjusted_size | free_chunk_inuse;

        free_chunk* new_head = (free_chunk*)get_next_chunk(alloc_block);
        new_head->meta_data.size = remaining_space - CHUNK_HEADER_SIZE;
        new_head->meta_data.size |= PREV_INUSE;
        new_head->meta_data.prev_size = adjusted_size;
        
        add_chunk_to_free_list(new_head);
        printf("Malloc: Split bock. Allocated %zu, New free remainder %zu\n", adjusted_size, new_head->meta_data.size & ~0xF);

    } else {
        // no splitting
        alloc_block->size = free_chunk_size | free_chunk_inuse;
        printf("Malloc: Used whole block %zu, for requested %zu (adjusted to %zu)\n", free_chunk_size, size, adjusted_size);
    }

    // Set PREV_INUSE of the next chunk
    meta_data* next_chunk = get_next_chunk(alloc_block);
    if (next_chunk != NULL) {
        next_chunk->size |= PREV_INUSE;
        if (!(remaining_space >= CHUNK_HEADER_SIZE)) {
            next_chunk->prev_size = alloc_block->size & ~0xF;
        }
    }
    pthread_mutex_unlock(&alloc_lock);
    return (void*)(alloc_block + 1);
}

void mem_free(void* ptr) {
    pthread_mutex_lock(&alloc_lock);
    if (!ptr) {
        printf("Free: Attemted to free NULL ptr\n");
        pthread_mutex_unlock(&alloc_lock);
        return;
    }

    printf("\nFree request for: %p\n", ptr);

    meta_data* meta = ((meta_data*)ptr-1);

    if (meta < map_start || meta > map_end) {
        perror("Invalid pointer - metadata out of mapped region\n");
        pthread_mutex_unlock(&alloc_lock);
        return;
    }

    free_chunk* new_head = (free_chunk*)meta;

    size_t block_size = meta->size & ~0xF;
    size_t block_inuse = meta->size & PREV_INUSE;

    // Coalesce backwards
    if (!(block_inuse) && (void*)meta > map_start) {
        free_chunk* prev_adjacent_chunk = (free_chunk*)get_prev_chunk(new_head);
        
        if (prev_adjacent_chunk != NULL) {
            printf("coalescing backwards\n");
            remove_free(prev_adjacent_chunk);
            size_t prev_size = prev_adjacent_chunk->meta_data.size & ~0xF;
            size_t prev_prev_inuse = prev_adjacent_chunk->meta_data.size & PREV_INUSE;
            
            prev_adjacent_chunk->meta_data.size = prev_size + block_size + CHUNK_HEADER_SIZE;
            prev_adjacent_chunk->meta_data.size |= prev_prev_inuse;

            new_head = prev_adjacent_chunk;
            block_size = prev_adjacent_chunk->meta_data.size & ~0xF;
            block_inuse = prev_prev_inuse;
        }
    }

    // Coalesce forwards
    meta_data* next_adjacent_meta = get_next_chunk((meta_data*)new_head);
    if (next_adjacent_meta != NULL) {
        meta_data* chunk_after_next = get_next_chunk((meta_data*)next_adjacent_meta);
        if (chunk_after_next != NULL && !(chunk_after_next->size & PREV_INUSE)) {
            printf("coalescing forwards\n");
            remove_free((meta_data*)next_adjacent_meta);
            size_t next_size = next_adjacent_meta->size & -0xF;
            new_head->meta_data.size = block_size + next_size + CHUNK_HEADER_SIZE;
            new_head->meta_data.size |= block_inuse;
            block_size = new_head->meta_data.size & ~0xF;
        }
    }
    add_chunk_to_free_list(new_head);

    // set next chunk's prev_size and reset prev_inuse
    meta_data* next_chunk = get_next_chunk((meta_data*)new_head);
    if (next_chunk != NULL) {
        next_chunk->prev_size = (new_head->meta_data.size & ~0xF);
        next_chunk->size &= ~PREV_INUSE;
    }
    printf("Free successful for original ptr. Final free block: %p, new payload: %zu\n", (void*)new_head, block_size);
    pthread_mutex_unlock(&alloc_lock);
}
