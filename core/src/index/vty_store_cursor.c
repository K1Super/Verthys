/*
 * vty_store_cursor.c — 升序游标
 */

#include "vty_store_internal.h"

struct VtyStoreCursor {
    VtyStore *s;
    uint8_t keyspace;
    uint8_t target[VTY_STORE_KEY_MAX];
    uint16_t target_len;
    uint64_t root_id;
    uint8_t root_level;
    uint8_t depth;
    uint64_t node_id[VTY_STORE_MAX_LEVEL + 2u];
    uint16_t node_idx[VTY_STORE_MAX_LEVEL + 2u];
    uint8_t node_level[VTY_STORE_MAX_LEVEL + 2u];
    VtyMemNode *leaf;
    uint16_t leaf_pos;
    int done;
};


static uint16_t lower_bound_entries(const VtyMemEntry *e, uint32_t n,
                                    const uint8_t *key, uint16_t key_len)
{
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        if (vty_st_key_cmp(e[mid].key, e[mid].key_len, key, key_len) < 0) lo = mid + 1u;
        else hi = mid;
    }
    return (uint16_t)lo;
}

static int cursor_advance(VtyStoreCursor *c);

static int cursor_descend(VtyStoreCursor *c, uint64_t id, uint8_t level, int first)
{
    uint32_t guard = 0;

    for (;;) {
        VtyMemNode node;
        int rc;

        if (++guard > VTY_STORE_MAX_LEVEL + 2u) return VTY_E_CORRUPT;
        memset(&node, 0, sizeof(node));
        rc = vty_st_node_read(c->s, id, level, &node, NULL);
        if (rc != VTY_OK) return rc;

        if (node.type == VTY_NODE_LEAF) {
            c->leaf = (VtyMemNode *)vty_alloc(sizeof(VtyMemNode));
            if (c->leaf == NULL) {
                vty_st_node_free(&node);
                return VTY_E_RESOURCE;
            }
            *c->leaf = node;
            c->leaf_pos = first
                ? lower_bound_entries(node.e, node.n, c->target, c->target_len)
                : 0;
            if (c->leaf_pos >= node.n) return cursor_advance(c);
            return VTY_OK;
        }

        if (c->depth >= VTY_STORE_MAX_LEVEL + 1u) {
            vty_st_node_free(&node);
            return VTY_E_CORRUPT;
        }
        c->node_idx[c->depth] = first
            ? lower_bound_entries(node.e, node.n, c->target, c->target_len)
            : 0;
        if (c->node_idx[c->depth] >= node.n) c->node_idx[c->depth] = (uint16_t)(node.n - 1u);
        c->node_id[c->depth] = id;
        c->node_level[c->depth] = level;
        c->depth++;

        id = node.e[c->node_idx[c->depth - 1u]].child_id;
        level = (uint8_t)(level - 1u);
        vty_st_node_free(&node);
    }
}

static int cursor_advance(VtyStoreCursor *c)
{
    if (c->leaf != NULL) {
        vty_st_node_free(c->leaf);
        vty_free(c->leaf, sizeof(VtyMemNode));
        c->leaf = NULL;
    }

    while (c->depth > 0) {
        VtyMemNode parent;
        uint32_t i;
        int rc;

        memset(&parent, 0, sizeof(parent));
        rc = vty_st_node_read(c->s, c->node_id[c->depth - 1u],
                       c->node_level[c->depth - 1u], &parent, NULL);
        if (rc != VTY_OK) return rc;
        i = c->node_idx[c->depth - 1u];
        c->depth--;
        if (i + 1u < parent.n) {
            uint64_t child = parent.e[i + 1u].child_id;
            uint8_t clevel = (uint8_t)(c->node_level[c->depth] - 1u);
            c->node_idx[c->depth] = (uint16_t)(i + 1u);
            c->depth++;
            vty_st_node_free(&parent);
            return cursor_descend(c, child, clevel, 0);
        }
        vty_st_node_free(&parent);
    }

    c->done = 1;
    return VTY_OK;
}

int vty_store_cursor_open(VtyStore *s, uint8_t keyspace,
                          const uint8_t *start_key, size_t start_key_len,
                          VtyStoreCursor **out)
{
    VtyStoreCursor *c;
    int rc;

    if (s == NULL || out == NULL) return VTY_E_INVALID;
    if (start_key == NULL && start_key_len != 0) return VTY_E_INVALID;
    if (start_key_len + 1u > VTY_STORE_KEY_MAX) return VTY_E_INVALID;

    *out = NULL;
    c = (VtyStoreCursor *)vty_alloc(sizeof(VtyStoreCursor));
    if (c == NULL) return VTY_E_RESOURCE;
    c->s = s;
    c->keyspace = keyspace;
    c->target[0] = keyspace;
    if (start_key_len != 0) memcpy(c->target + 1, start_key, start_key_len);
    c->target_len = (uint16_t)(start_key_len + 1u);
    c->root_id = s->loc.root_node_id;
    c->root_level = s->loc.level;
    c->leaf = NULL;
    c->depth = 0;
    c->done = 0;

    if (c->root_id == 0u) {
        c->done = 1;
        *out = c;
        return VTY_OK;
    }
    rc = cursor_descend(c, c->root_id, c->root_level, 1);
    if (rc != VTY_OK) {
        vty_store_cursor_close(c);
        return rc;
    }
    *out = c;
    return VTY_OK;
}

int vty_store_cursor_next(VtyStoreCursor *c, int *done,
                          uint8_t **key, size_t *key_len,
                          uint8_t **value, size_t *value_len)
{
    if (c == NULL || done == NULL || key == NULL || key_len == NULL ||
        value == NULL || value_len == NULL) {
        return VTY_E_INVALID;
    }
    *done = 0;
    *key = NULL;
    *key_len = 0;
    *value = NULL;
    *value_len = 0;

    for (;;) {
        const VtyMemEntry *e;
        int rc;

        if (c->done || c->leaf == NULL) {
            *done = 1;
            return VTY_OK;
        }
        if (c->leaf_pos >= c->leaf->n) {
            rc = cursor_advance(c);
            if (rc != VTY_OK) return rc;
            continue;
        }

        e = &c->leaf->e[c->leaf_pos];
        if (e->key_len == 0) return VTY_E_CORRUPT;
        if (e->key[0] < c->keyspace) {
            c->leaf_pos++;
            continue;
        }
        if (e->key[0] > c->keyspace) {
            *done = 1;
            return VTY_OK;
        }

        c->leaf_pos++;
        {
            size_t klen = (size_t)e->key_len - 1u;
            uint8_t *k = NULL;
            if (klen != 0) {
                k = (uint8_t *)vty_alloc(klen);
                if (k == NULL) return VTY_E_RESOURCE;
                memcpy(k, e->key + 1, klen);
            }
            *key = k;
            *key_len = klen;
        }
        if (e->val_len != 0) {
            uint8_t *v = (uint8_t *)vty_alloc(e->val_len);
            if (v == NULL) {
                if (*key != NULL) vty_free(*key, *key_len);
                *key = NULL;
                *key_len = 0;
                return VTY_E_RESOURCE;
            }
            memcpy(v, e->val, e->val_len);
            *value = v;
            *value_len = e->val_len;
        }
        return VTY_OK;
    }
}

void vty_store_cursor_close(VtyStoreCursor *c)
{
    if (c == NULL) return;
    if (c->leaf != NULL) {
        vty_st_node_free(c->leaf);
        vty_free(c->leaf, sizeof(VtyMemNode));
        c->leaf = NULL;
    }
    vty_free(c, sizeof(VtyStoreCursor));
}
