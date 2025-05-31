#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define PREV_INUSE 0x01
#define MIN_SIZE 0xFF

#define MIN_CHUNK_SIZE 32

typedef struct {
    size_t __prev_size;
    size_t size;
} meta_data;

typedef struct free_chunk {
    meta_data __meta_data;
    struct free_chunk* fd;
    struct free_chunk* bk;
 } free_chunk;

void* map = NULL;

free_chunk* free_head;

void init_map(size_t map_size) {
    map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        printf("Failed to create map");
        exit;
    }
    meta_data* __free_list = map;
    __free_list->__prev_size = 0;
    __free_list->size = map_size;

    free_head = map;
    free_head->__meta_data.size = map_size;
    free_head->__meta_data.__prev_size = 0;
    free_head->fd = NULL;
    free_head->bk = NULL;

}

void new_free_head(free_chunk** __new_head) {
    free_head->bk = *__new_head;
    (*__new_head)->fd = free_head;
    (*__new_head)->bk = NULL;
    free_head = *__new_head;
}

void *mem_malloc(size_t __size) {
    if (map == NULL) {
        init_map(4096);
    }
    if (free_head->__meta_data.size > __size) {
        size_t head_size = free_head->__meta_data.size;
        meta_data* __meta = (meta_data*)free_head;
        __meta->size = (__size + 15) & ~0xF;
        __meta->__prev_size = 0;
        if (head_size - __meta->size > MIN_CHUNK_SIZE) {
            free_chunk* __new_head = (free_chunk*)((char*)(__meta+1) + (__meta->size));
            new_free_head(&__new_head);
        }
        return (void*)(__meta + 1);
    } else {
        return NULL;
    }
    
}

void mem_free(void *__ptr) {
    meta_data* __meta = ((meta_data*)__ptr-1);
    free_chunk* __new_head = (free_chunk*)__meta;
    new_free_head(&__new_head);
    __new_head->__meta_data.size = __meta->size;
}

void create_nums(int** nums, size_t size) {
    *nums = mem_malloc(size * sizeof(int));
    for (int i = 0; i < size; i++) {
        (*nums)[i] = i;
    }
}

void print_nums(int* nums, size_t size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", *(nums+i));
    }
    printf("\n");
}

int main() {
    int* nums;
    size_t size = 50;
    create_nums(&nums, size);
    print_nums(nums, size);
    mem_free(nums);
    int* nums2;
    size_t size2 = 40;
    create_nums(&nums2, size2);
    print_nums(nums2, size2);
    mem_free(nums2);
    print_nums(nums2, size2);
    munmap(map, 4096);
    // printf("%ld\n", sizeof(free_chunk));

    return 0;
}