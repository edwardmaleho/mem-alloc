#include "mem-alloc.h"


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