#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void* map = NULL;

struct {
    void *__next_ptr;
    size_t size;
} typedef meta_data;

void init_map(size_t map_size) {
    map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        printf("Failed to create map");
        exit;
    }
}

void *mem_malloc(size_t __size) {
    if (map == NULL) {
        init_map(4096);
    }
    size_t meta_size = sizeof(meta_data);
    // void* __ptr = malloc(meta_size + __size);
    void* __ptr = map;
    meta_data *__meta = __ptr;
    __meta->size = __size;
    __meta->__next_ptr = NULL;
    printf("meta: size: %ld next: %p\n", __meta->size, __meta->__next_ptr);
    return (void*)((char*)__ptr + meta_size/8);
}

void mem_free(void *__ptr) {
    void *__meta = (void*)((char*)__ptr-2);
    // free(__meta);
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
    munmap(map, 4096);

    return 0;
}