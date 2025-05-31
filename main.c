#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define PREV_INUSE 0x01
#define MIN_SIZE 0xFF

#define MIN_CHUNK_SIZE 32

typedef struct {
    size_t prev_size;
    size_t size;
} meta_data;

typedef struct free_chunk {
    meta_data meta_data;
    struct free_chunk* fd;
    struct free_chunk* bk;
 } free_chunk;

void* map = NULL;

// free_head fd-> <-bk old_free_head
free_chunk* free_head;

void print_free_block(free_chunk* chunk) {
    printf("Ptr: %p fd: %p bk: %p size: %ld \n", chunk, chunk->fd, chunk->bk, chunk->meta_data.size);
}

void init_map(size_t map_size) {
    map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        printf("Failed to create map");
        exit;
    }
    // meta_data* free_list = map;
    // free_list->prev_size = 0;
    // free_list->size = map_size;

    free_head = map;
    free_head->meta_data.size = map_size - sizeof(meta_data);
    free_head->meta_data.prev_size = 0;
    free_head->fd = NULL;
    free_head->bk = NULL;
    print_free_block(free_head);

}

void new_free_head(free_chunk** new_head) {
    free_head->bk = *new_head;
    (*new_head)->fd = free_head;
    (*new_head)->bk = NULL;
    free_head = *new_head;
    printf("Old head: ");
    print_free_block(free_head->fd);
    printf("New head: ");
    print_free_block(free_head);
}

void *mem_malloc(size_t size) {
    if (map == NULL) {
        init_map(4096);
    }
    if (free_head->meta_data.size > size) {
        size_t head_size = free_head->meta_data.size;
        meta_data* meta = (meta_data*)free_head;
        meta->size = (size + 15) & ~0xF;
        meta->prev_size = 0;
        if (head_size - meta->size > MIN_CHUNK_SIZE) {
            free_chunk* new_head = (free_chunk*)((char*)(meta+1) + (meta->size));
            new_head->meta_data.size = head_size - meta->size;
            new_free_head(&new_head);
        }
        return (void*)(meta + 1);
    } else {
        return NULL;
    }
    
}

void mem_free(void *ptr) {
    meta_data* meta = ((meta_data*)ptr-1);
    free_chunk* new_head = (free_chunk*)meta;
    new_free_head(&new_head);
    new_head->meta_data.size = meta->size;
}

void print_nums(int* nums, size_t size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", *(nums+i));
    }
    printf("\n");
}

void create_nums(int** nums, size_t size) {
    *nums = mem_malloc(size * sizeof(int));
    for (int i = 0; i < size; i++) {
        (*nums)[i] = i;
    }
    print_nums(*nums, size);
}

int main() {
    // int* nums;
    // size_t size = 50;
    // create_nums(&nums, size);
    // // mem_free(nums);
    // int* nums2;
    // size_t size2 = 40;
    // create_nums(&nums2, size2);
    // mem_free(nums2);
    // mem_free(nums);
    // print_nums(nums2, size2);

    int* nums1;
    int* nums2;
    int* nums3;
    create_nums(&nums1, 70);
    mem_free(nums1);
    
    create_nums(&nums2, 60);
    mem_free(nums2);

    print_nums(nums1, 50);
    munmap(map, 4096);

    return 0;
}