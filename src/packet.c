#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include "packet.h"

// Two payload size classes: MTU sized packets and the rare jumbo / offloaded ones.
#define POOL_SMALL_SIZE 2048u
#define POOL_LARGE_SIZE ((UINT)WINDIVERT_MTU_MAX + 1u)

// Each pooled block starts with an SLIST_ENTRY; the payload follows at an aligned offset.
#define BLOCK_HDR ((sizeof(SLIST_ENTRY) + MEMORY_ALLOCATION_ALIGNMENT - 1) & ~(size_t)(MEMORY_ALLOCATION_ALIGNMENT - 1))

typedef struct {
    SLIST_HEADER freeList;
    size_t payloadSize;
    volatile LONG allocated;
    volatile LONG inUse;
} Pool;

static Pool nodePool, smallPool, largePool;
static volatile LONG poolReady = 0;

static void poolInit(Pool *p, size_t payloadSize) {
    InitializeSListHead(&p->freeList);
    p->payloadSize = payloadSize;
    p->allocated = 0;
    p->inUse = 0;
}

static void *poolGet(Pool *p) {
    PSLIST_ENTRY e = InterlockedPopEntrySList(&p->freeList);
    char *block;
    if (e == NULL) {
        block = (char *)_aligned_malloc(BLOCK_HDR + p->payloadSize, MEMORY_ALLOCATION_ALIGNMENT);
        if (block == NULL) {
            return NULL;
        }
        InterlockedIncrement(&p->allocated);
    } else {
        block = (char *)e;
    }
    InterlockedIncrement(&p->inUse);
    return block + BLOCK_HDR;
}

static void poolPut(Pool *p, void *payload) {
    char *block = (char *)payload - BLOCK_HDR;
    InterlockedDecrement(&p->inUse);
    InterlockedPushEntrySList(&p->freeList, (PSLIST_ENTRY)block);
}

static void poolDrain(Pool *p) {
    PSLIST_ENTRY e;
    while ((e = InterlockedPopEntrySList(&p->freeList)) != NULL) {
        _aligned_free(e);
        InterlockedDecrement(&p->allocated);
    }
}

void packetPoolInit(void) {
    if (InterlockedCompareExchange(&poolReady, 1, 0) != 0) {
        return;
    }
    poolInit(&nodePool, sizeof(PacketNode));
    poolInit(&smallPool, POOL_SMALL_SIZE);
    poolInit(&largePool, POOL_LARGE_SIZE);
    InterlockedExchange(&poolReady, 2);
}

static void poolEnsureReady(void) {
    if (poolReady == 2) return;
    packetPoolInit();
    while (poolReady != 2) {
        SwitchToThread();
    }
}

void packetPoolShutdown(void) {
    if (poolReady != 2) return;
    poolDrain(&nodePool);
    poolDrain(&smallPool);
    poolDrain(&largePool);
}

void packetPoolGetStats(PacketPoolStats *out) {
    out->nodesInUse = nodePool.inUse;
    out->nodesAllocated = nodePool.allocated;
    out->smallInUse = smallPool.inUse;
    out->smallAllocated = smallPool.allocated;
    out->largeInUse = largePool.inUse;
    out->largeAllocated = largePool.allocated;
}

static Pool *poolForCapacity(UINT capacity) {
    return capacity <= POOL_SMALL_SIZE ? &smallPool : &largePool;
}

PacketNode *packetAlloc(const void *buf, UINT len, const WINDIVERT_ADDRESS *addr) {
    PacketNode *n;
    Pool *bp;
    poolEnsureReady();
    if (len > POOL_LARGE_SIZE) {
        return NULL;
    }
    n = (PacketNode *)poolGet(&nodePool);
    if (n == NULL) {
        return NULL;
    }
    memset(n, 0, sizeof(*n));
    bp = poolForCapacity(len);
    n->packet = (char *)poolGet(bp);
    if (n->packet == NULL) {
        poolPut(&nodePool, n);
        return NULL;
    }
    n->capacity = (UINT)bp->payloadSize;
    if (len > 0 && buf != NULL) {
        memcpy(n->packet, buf, len);
    }
    n->packetLen = len;
    if (addr != NULL) {
        n->addr = *addr;
    }
    n->ruleIndex = PACKET_RULE_NONE;
    return n;
}

PacketNode *packetClone(const PacketNode *src) {
    PacketNode *n = packetAlloc(src->packet, src->packetLen, &src->addr);
    if (n == NULL) {
        return NULL;
    }
    n->captureTime = src->captureTime;
    n->releaseTime = src->releaseTime;
    n->flowHash = src->flowHash;
    n->processId = src->processId;
    n->ruleIndex = src->ruleIndex;
    n->flags = (uint16_t)(src->flags | PN_FLAG_DUPLICATE);
    return n;
}

BOOL packetReserve(PacketNode *node, UINT capacity) {
    char *bigger;
    if (capacity <= node->capacity) {
        return TRUE;
    }
    if (capacity > POOL_LARGE_SIZE) {
        return FALSE;
    }
    bigger = (char *)poolGet(&largePool);
    if (bigger == NULL) {
        return FALSE;
    }
    memcpy(bigger, node->packet, node->packetLen);
    poolPut(poolForCapacity(node->capacity), node->packet);
    node->packet = bigger;
    node->capacity = (UINT)largePool.payloadSize;
    return TRUE;
}

void packetFree(PacketNode *node) {
    assert(node->prev == NULL && node->next == NULL);
    poolPut(poolForCapacity(node->capacity), node->packet);
    node->packet = NULL;
    poolPut(&nodePool, node);
}

// ---- list ----

void listInit(PacketList *l) {
    l->head.next = &l->tail;
    l->head.prev = NULL;
    l->tail.prev = &l->head;
    l->tail.next = NULL;
    l->count = 0;
}

void listEnsureInit(PacketList *l) {
    if (l->head.next == NULL) {
        listInit(l);
    }
}

int listEmpty(const PacketList *l) {
    return l->head.next == &l->tail;
}

int listCount(const PacketList *l) {
    return l->count;
}

PacketNode *listFirst(PacketList *l) {
    return l->head.next == &l->tail ? NULL : l->head.next;
}

PacketNode *listLast(PacketList *l) {
    return l->tail.prev == &l->head ? NULL : l->tail.prev;
}

PacketNode *listNext(PacketList *l, PacketNode *n) {
    return n->next == &l->tail ? NULL : n->next;
}

PacketNode *listPrev(PacketList *l, PacketNode *n) {
    return n->prev == &l->head ? NULL : n->prev;
}

PacketNode *listUnlink(PacketList *l, PacketNode *n) {
    assert(n != &l->head && n != &l->tail);
    assert(n->prev != NULL && n->next != NULL);
    n->prev->next = n->next;
    n->next->prev = n->prev;
    n->prev = n->next = NULL;
    --l->count;
    return n;
}

void listInsertAfter(PacketList *l, PacketNode *n, PacketNode *target) {
    assert(n != &l->head && n != &l->tail && target != &l->tail);
    assert(n->prev == NULL && n->next == NULL);
    n->prev = target;
    n->next = target->next;
    target->next->prev = n;
    target->next = n;
    ++l->count;
}

void listInsertBefore(PacketList *l, PacketNode *n, PacketNode *target) {
    assert(n != &l->head && n != &l->tail && target != &l->head);
    assert(n->prev == NULL && n->next == NULL);
    n->next = target;
    n->prev = target->prev;
    target->prev->next = n;
    target->prev = n;
    ++l->count;
}

void listPushBack(PacketList *l, PacketNode *n) {
    listInsertBefore(l, n, &l->tail);
}

void listPushFront(PacketList *l, PacketNode *n) {
    listInsertAfter(l, n, &l->head);
}

void listAppendAll(PacketList *dst, PacketList *src) {
    PacketNode *first, *last;
    if (listEmpty(src)) {
        return;
    }
    first = src->head.next;
    last = src->tail.prev;
    first->prev = dst->tail.prev;
    last->next = &dst->tail;
    dst->tail.prev->next = first;
    dst->tail.prev = last;
    dst->count += src->count;
    listInit(src);
}

void listPrependAll(PacketList *dst, PacketList *src) {
    PacketNode *first, *last;
    if (listEmpty(src)) {
        return;
    }
    first = src->head.next;
    last = src->tail.prev;
    last->next = dst->head.next;
    first->prev = &dst->head;
    dst->head.next->prev = last;
    dst->head.next = first;
    dst->count += src->count;
    listInit(src);
}

void listSwap(PacketList *l, PacketNode *a, PacketNode *b) {
    PacketNode *pa, *pb;
    if (a == b) {
        return;
    }
    if (a->next == b) {
        listUnlink(l, b);
        listInsertBefore(l, b, a);
        return;
    }
    if (b->next == a) {
        listUnlink(l, a);
        listInsertBefore(l, a, b);
        return;
    }
    pa = a->prev;
    pb = b->prev;
    listUnlink(l, a);
    listUnlink(l, b);
    listInsertAfter(l, a, pb);
    listInsertAfter(l, b, pa);
}

void listFreeAll(PacketList *l) {
    PacketNode *n;
    while ((n = listFirst(l)) != NULL) {
        packetFree(listUnlink(l, n));
    }
}
