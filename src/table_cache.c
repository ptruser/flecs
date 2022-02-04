#include "private_api.h"

static
void ensure_index(
    ecs_table_cache_t *cache)
{
    if (!cache->index) {
        cache->index = ecs_map_new(ecs_table_cache_hdr_t*, 0);
    }
}

static
void table_cache_list_remove(
    ecs_table_cache_t *cache,
    ecs_table_cache_hdr_t *elem)
{
    ecs_table_cache_hdr_t *next = elem->next;
    ecs_table_cache_hdr_t *prev = elem->prev;

    if (next) {
        next->prev = prev;
    }
    if (prev) {
        prev->next = next;
    }

    cache->empty_table_count -= !!elem->empty;
    cache->table_count -= !elem->empty;

    if (cache->empty_tables == elem) {
        cache->empty_tables = next;
    } else if (cache->tables == elem) {
        cache->tables = next;
    }
}

static
void table_cache_list_insert(
    ecs_table_cache_t *cache,
    ecs_table_cache_hdr_t *elem)
{
    ecs_table_cache_hdr_t *first;
    if (elem->empty) {
        first = cache->empty_tables;
        cache->empty_tables = elem;
        cache->empty_table_count ++;
    } else {
        first = cache->tables;
        cache->tables = elem;
        cache->table_count ++;
    }

    elem->next = first;
    elem->prev = NULL;

    if (first) {
        first->prev = elem;
    }
}

void _ecs_table_cache_init(
    ecs_table_cache_t *cache,
    ecs_size_t size,
    ecs_sparse_t *storage,
    ecs_poly_t *parent,
    void(*free_payload)(ecs_poly_t*, void*))
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(size >= ECS_SIZEOF(ecs_table_cache_hdr_t), 
        ECS_INTERNAL_ERROR, NULL);

    cache->index = NULL;
    cache->storage = storage;
    cache->tables = NULL;
    cache->empty_tables = NULL;
    cache->size = size;
    cache->parent = parent;
    cache->free_payload = free_payload;
}

static
void free_payload(
    ecs_table_cache_t *cache,
    ecs_table_cache_hdr_t *first)
{
    void(*free_payload_func)(ecs_poly_t*, void*) = cache->free_payload;
    if (free_payload_func) {
        ecs_sparse_t *storage = cache->storage;
        ecs_poly_t *parent = cache->parent;
        ecs_table_cache_hdr_t *cur, *next = first;

        while ((cur = next)) {
            next = cur->next;
            free_payload_func(parent, cur);
            flecs_sparse_remove(storage, cur->storage_id);
        }
    }
}

void ecs_table_cache_fini(
    ecs_table_cache_t *cache)
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_map_free(cache->index);
    free_payload(cache, cache->tables);
    free_payload(cache, cache->empty_tables);
}

bool ecs_table_cache_is_initialized(
    ecs_table_cache_t *cache)
{
    return cache->size != 0;
}

void* _ecs_table_cache_insert(
    ecs_table_cache_t *cache,
    ecs_size_t size,
    const ecs_table_t *table)
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(size == cache->size, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(!table || (_ecs_table_cache_get(cache, size, table) == NULL), 
        ECS_INTERNAL_ERROR, NULL);

    bool empty;
    if (!table) {
        empty = false;
    } else {
        empty = ecs_table_count(table) == 0;
    }

    ecs_table_cache_hdr_t *result = _flecs_sparse_add(cache->storage, size);
    result->storage_id = (uint32_t)flecs_sparse_last_id(cache->storage);
    result->table = (ecs_table_t*)table;
    result->empty = empty;

    table_cache_list_insert(cache, result);

    if (table) {
        ensure_index(cache);
        ecs_map_set_ptr(cache->index, table->id, result);
    }

    ecs_assert(empty || cache->tables != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(!empty || cache->empty_tables != NULL, ECS_INTERNAL_ERROR, NULL);

    return result;
}

ecs_table_cache_hdr_t* _ecs_table_cache_get(
    const ecs_table_cache_t *cache,
    ecs_size_t size,
    const ecs_table_t *table)
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(size == cache->size, ECS_INTERNAL_ERROR, NULL);
    (void)size;
    return ecs_map_get_ptr(cache->index, ecs_table_cache_hdr_t*, table->id);
}

bool _ecs_table_cache_remove(
    ecs_table_cache_t *cache,
    ecs_size_t size,
    const ecs_table_t *table)
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(size == cache->size, ECS_INTERNAL_ERROR, NULL);
    (void)size;

    ecs_table_cache_hdr_t *elem = ecs_map_get_ptr(
        cache->index, ecs_table_cache_hdr_t*, table->id);
    if (!elem) {
        return false;
    }

    if (cache->free_payload) {
        cache->free_payload(cache->parent, elem);
    }

    table_cache_list_remove(cache, elem);

    flecs_sparse_remove(cache->storage, elem->storage_id);
    flecs_sparse_set_generation(cache->storage, elem->storage_id);

    if (ecs_map_remove(cache->index, table->id) == 0) {
        ecs_map_free(cache->index);
        cache->index = NULL;
        return true;
    } else {
        return false;
    }
}

bool ecs_table_cache_set_empty(
    ecs_table_cache_t *cache,
    const ecs_table_t *table,
    bool empty)
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_table_cache_hdr_t *elem = ecs_map_get_ptr(
        cache->index, ecs_table_cache_hdr_t*, table->id);
    if (!elem) {
        return false;
    }

    if (elem->empty == empty) {
        return false;
    }

    table_cache_list_remove(cache, elem);
    elem->empty = empty;
    table_cache_list_insert(cache, elem);

    return true;
}

void _ecs_table_cache_fini_delete_all(
    ecs_world_t *world,
    ecs_table_cache_t *cache,
    ecs_size_t size)
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    if (!cache->index) {
        return;
    }

    ecs_assert(cache->size == size, ECS_INTERNAL_ERROR, NULL);
    (void)size;

    /* Temporarily set index to NULL, so that when the table tries to remove
     * itself from the cache it won't be able to. This keeps the arrays we're
     * iterating over consistent */
    ecs_map_t *index = cache->index;
    cache->index = NULL;

    ecs_table_cache_hdr_t *cur, *next = cache->tables;
    while ((cur = next)) {
        flecs_delete_table(world, cur->table);
        next = cur->next;
    }

    next = cache->empty_tables;
    while ((cur = next)) {
        flecs_delete_table(world, cur->table);
        next = cur->next;
    }

    cache->index = index;

    ecs_table_cache_fini(cache);
}

bool flecs_table_cache_iter(
    ecs_table_cache_t *cache,
    ecs_table_cache_iter_t *out)
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(out != NULL, ECS_INTERNAL_ERROR, NULL);
    out->next = cache->tables;
    out->cur = NULL;
    return out->next != NULL;
}

bool flecs_table_cache_empty_iter(
    ecs_table_cache_t *cache,
    ecs_table_cache_iter_t *out)
{
    ecs_assert(cache != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(out != NULL, ECS_INTERNAL_ERROR, NULL);
    out->next = cache->empty_tables;
    out->cur = NULL;
    return out->next != NULL;
}

ecs_table_cache_hdr_t* _flecs_table_cache_next(
    ecs_table_cache_iter_t *it)
{
    ecs_table_cache_hdr_t *next = it->next;
    if (!next) {
        return false;
    }

    it->cur = next;
    it->next = next->next;
    return next;
}
