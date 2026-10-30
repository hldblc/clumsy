// Packet nodes, FIFO packet lists and the pooled allocator behind them.
//
// Lists are in send order: head.next is sent first, tail.prev last.
// Nodes come from lock-free pools so the capture thread can allocate while the
// processor thread frees without taking a lock.
#pragma once
#include <stdint.h>
#include <windows.h>
#include "windivert.h"

// What modules did to a packet; carried into the packet log and statistics.
#define PN_FLAG_DUPLICATE  0x0001
#define PN_FLAG_TAMPERED   0x0002
#define PN_FLAG_RST        0x0004
#define PN_FLAG_LAGGED     0x0008
#define PN_FLAG_REORDERED  0x0010
#define PN_FLAG_THROTTLED  0x0020
#define PN_FLAG_SHAPED     0x0040
#define PN_FLAG_FRAGMENT   0x0080
#define PN_FLAG_INJECTED   0x0100
#define PN_FLAG_TCPMOD     0x0200

#define PACKET_RULE_NONE 0xFFFF

typedef struct PacketNode {
    struct PacketNode *prev, *next;
    char *packet;
    UINT packetLen;
    UINT capacity;          // bytes available at packet
    WINDIVERT_ADDRESS addr;
    int64_t captureTime;    // clockNowUs() when the engine received it
    int64_t releaseTime;    // scratch for time based modules (lag)
    uint64_t flowHash;      // canonical, direction independent 5-tuple hash
    uint32_t processId;     // owning process if known, else 0
    uint16_t ruleIndex;     // rule that claimed the packet, PACKET_RULE_NONE if none
    uint16_t flags;         // PN_FLAG_*
} PacketNode;

typedef struct PacketList {
    PacketNode head, tail;  // sentinels
    int count;
} PacketList;

typedef struct {
    LONG nodesInUse, nodesAllocated;
    LONG smallInUse, smallAllocated;
    LONG largeInUse, largeAllocated;
} PacketPoolStats;

// ---- pool ----
void packetPoolInit(void);
void packetPoolShutdown(void);
PacketNode *packetAlloc(const void *buf, UINT len, const WINDIVERT_ADDRESS *addr);
PacketNode *packetClone(const PacketNode *src);
BOOL packetReserve(PacketNode *node, UINT capacity);
void packetFree(PacketNode *node);
void packetPoolGetStats(PacketPoolStats *out);

// ---- list ----
void listInit(PacketList *l);
void listEnsureInit(PacketList *l);     // init only if never initialized (zeroed storage)
int  listEmpty(const PacketList *l);
int  listCount(const PacketList *l);
PacketNode *listFirst(PacketList *l);   // NULL when empty
PacketNode *listLast(PacketList *l);
PacketNode *listNext(PacketList *l, PacketNode *n);   // NULL at end
PacketNode *listPrev(PacketList *l, PacketNode *n);   // NULL at start
PacketNode *listUnlink(PacketList *l, PacketNode *n); // returns n
void listPushBack(PacketList *l, PacketNode *n);
void listPushFront(PacketList *l, PacketNode *n);
void listInsertAfter(PacketList *l, PacketNode *n, PacketNode *target);   // target may be &l->head
void listInsertBefore(PacketList *l, PacketNode *n, PacketNode *target);  // target may be &l->tail
void listAppendAll(PacketList *dst, PacketList *src);   // move all of src to the back of dst
void listPrependAll(PacketList *dst, PacketList *src);  // move all of src to the front of dst
void listSwap(PacketList *l, PacketNode *a, PacketNode *b);
void listFreeAll(PacketList *l);
