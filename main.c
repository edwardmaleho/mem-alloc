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

pthread_mutex_t alloc_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    size_t prev_size;
    size_t size;
} meta_data;

typedef struct free_chunk {
    meta_data meta_data;
    struct free_chunk* fd;
    struct free_chunk* bk;
 } free_chunk;

void* map_start = NULL;
void* map_end = NULL;

// free_head fd-> <-bk old_free_head fd ->
free_chunk* free_head;

void print_free_block(free_chunk* chunk) {
    printf("Ptr: %p fd: %p bk: %p size: %ld \n", chunk, chunk->fd, chunk->bk, chunk->meta_data.size);
}
int i = 0;

void print_all_free(free_chunk* chunk) {
    i++;
    print_free_block(chunk);
    if (i < 10) {
        if (chunk->fd != NULL) {
            print_all_free(chunk->fd);
        }
    }
}

void print_free_block_info(free_chunk* chunk) {
    if (!chunk) {
        printf("Attempted to print NULL free block.\n");
        return;
    }
    printf("Ptr: %p, Size: %zu (Payload: %zu, PREV_INUSE: %s), PrevSize: %zu, FD: %p, BK: %p\n",
           (void*)chunk,
           chunk->meta_data.size,
           chunk->meta_data.size & ~0xF,
           (chunk->meta_data.size & PREV_INUSE) ? "SET" : "CLEAR",
           chunk->meta_data.prev_size,
           (void*)chunk->fd,
           (void*)chunk->bk);
}

void print_all_free_blocks_recursive(free_chunk* chunk, int depth) {
    if (depth > 20) { // Safety break for very long or circular lists
        printf("Stopping free list print due to depth limit.\n");
        return;
    }
    if (chunk == NULL) {
        if (depth == 0) printf("Free list is empty.\n");
        return;
    }
    print_free_block_info(chunk);
    if (chunk->fd != NULL) {
        print_all_free_blocks_recursive(chunk->fd, depth + 1);
    }
}

void print_all_free_list() {
    printf("\n--- Free List ---\n");
    print_all_free_blocks_recursive(free_head, 0);
    printf("--- End Free List ---\n");
}


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

void print_nums(int* nums, size_t size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", *(nums+i));
    }
    printf("\n");
}

void create_nums(int** nums, size_t size) {
    *nums = mem_malloc(size * sizeof(int));
    if (*nums == NULL) {
        printf("Failed to allocate memory for nums %zu\n", size);
        return;
    }
    for (int i = 0; i < size; i++) {
        (*nums)[i] = i;
    }
    print_nums(*nums, size);
}

int main() {
    printf("Starting memory allocator test.\n");
    printf("Size of meta_data: %zu\n", sizeof(meta_data));
    printf("Size of free_chunk: %zu\n", sizeof(free_chunk));
    printf("MIN_CHUNK_BODY_SIZE: %u\n", MIN_CHUNK_BODY_SIZE);
    printf("CHUNK_HEADER_SIZE: %u\n", CHUNK_HEADER_SIZE);
    printf("MIN_FREE_CHUNK_TOTAL_SIZE: %u\n", (CHUNK_HEADER_SIZE + MIN_CHUNK_BODY_SIZE));


    // Initialize map explicitly if not relying on first malloc
    init_map(MAPSIZE);
    print_all_free_list();

    int* nums1, *nums2, *nums3, *nums4, *nums5;

    printf("\n--- Test Case 1: Simple Allocations ---\n");
    create_nums(&nums1, 8); // 32 bytes
    print_all_free_list();
    create_nums(&nums2, 16); // 64 bytes
    print_all_free_list();
    create_nums(&nums3, 32); // 128 bytes
    print_all_free_list();

    printf("\n--- Test Case 2: Freeing and Coalescing ---\n");
    mem_free(nums2); // Free middle block
    nums2 = NULL;
    printf("After freeing nums2:\n");
    print_all_free_list();

    mem_free(nums1); // Free first block (should coalesce with next if nums2 was free space)
    nums1 = NULL;
    printf("After freeing nums1:\n");
    print_all_free_list();

    mem_free(nums3); // Free last block (should coalesce)
    nums3 = NULL;
    printf("After freeing nums3 (all should be one big block):\n");
    print_all_free_list();

    printf("\n--- Test Case 3: Re-allocation and Splitting --- \n");
    create_nums(&nums1, 10); // Allocate small chunk from large free block
    printf("After allocating nums1 (10 ints):\n");
    print_nums(nums1,10);
    print_all_free_list();

    create_nums(&nums2, 200); // Allocate larger chunk
    printf("After allocating nums2 (200 ints):\n");
     print_nums(nums2,200);
    print_all_free_list();

    mem_free(nums1);
    nums1 = NULL;
    printf("After freeing nums1 again:\n");
    print_all_free_list();


    printf("\n--- Test Case 4: Stress Alloc/Free ---\n");
    create_nums(&nums1, 5);
    create_nums(&nums2, 5);
    create_nums(&nums3, 5);
    create_nums(&nums4, 5);
    create_nums(&nums5, 5);
    print_all_free_list();

    mem_free(nums1); nums1 = NULL;
    mem_free(nums3); nums3 = NULL;
    mem_free(nums5); nums5 = NULL;
    printf("After freeing 1, 3, 5 (holes):\n");
    print_all_free_list();

    mem_free(nums2); nums2 = NULL;
    printf("After freeing 2 (coalesce with holes around it):\n");
    print_all_free_list();

    mem_free(nums4); nums4 = NULL;
    printf("After freeing 4 (all free):\n");
    print_all_free_list();

    printf("\n--- Test Case 5: Edge Cases & Full Consumption ---\n");
    // Try to allocate a very large chunk
    size_t large_alloc_count = (MAPSIZE - CHUNK_HEADER_SIZE - (CHUNK_HEADER_SIZE + MIN_CHUNK_BODY_SIZE)) / sizeof(int) -10; // almost fill
    if (large_alloc_count > 0) {
        create_nums(&nums1, large_alloc_count);
        print_all_free_list();
        create_nums(&nums2, 5); // small one after large
        print_all_free_list();
        mem_free(nums1); nums1 = NULL;
        mem_free(nums2); nums2 = NULL;
        print_all_free_list();
    }


    printf("\n--- Test Case 6: Allocating exact minimum size payload ---\n");
    int* min_payload_alloc = mem_malloc(MIN_CHUNK_BODY_SIZE);
    if(min_payload_alloc) min_payload_alloc[0] = 123;
    printf("Allocated minimum payload chunk at %p\n", (void*)min_payload_alloc);
    print_all_free_list();
    mem_free(min_payload_alloc);
    print_all_free_list();


    printf("Test finished.\n");
    munmap(map_start, MAPSIZE);
    map_start = NULL;
    map_end = NULL;
    free_head = NULL;

    return 0;
}