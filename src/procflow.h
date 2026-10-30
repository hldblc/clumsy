// Per-process targeting. A background WinDivert FLOW-layer sniff handle learns
// which process owns each connection (5-tuple -> pid), so a rule can be scoped
// to one executable. The 5-tuple table and the name matching are pure and
// unit tested; only the sniff thread needs the driver.
#pragma once
#include "common.h"

typedef struct {
    uint8_t proto;
    uint16_t portA, portB;      // canonical: (addrA,portA) <= (addrB,portB)
    uint32_t addrA[4], addrB[4];
} FlowKey;

typedef struct {
    FlowKey key;
    uint32_t pid;
    uint8_t used;
    int64_t lastSeen;
} FlowEntry;

typedef struct {
    FlowEntry *slots;
    int capacity;               // power of two
} FlowTable;

// pure helpers (testable)
void flowKeyFromEndpoints(FlowKey *k, uint8_t proto,
                          const uint32_t localAddr[4], uint16_t localPort,
                          const uint32_t remoteAddr[4], uint16_t remotePort);
int  flowKeyFromPacket(FlowKey *k, const void *packet, UINT len);  // 1 ok
int  flowKeyEqual(const FlowKey *a, const FlowKey *b);
uint64_t flowKeyHash(const FlowKey *k);

void flowTableInit(FlowTable *t, int capacity);
void flowTableFree(FlowTable *t);
void flowTableSet(FlowTable *t, const FlowKey *k, uint32_t pid, int64_t now);
uint32_t flowTableGet(FlowTable *t, const FlowKey *k);
void flowTableDel(FlowTable *t, const FlowKey *k);
int  flowTableCount(const FlowTable *t);

// does an executable path match a user supplied process filter?
// filter matches the base name with or without .exe, case-insensitive;
// an empty filter matches nothing here (callers treat empty as "any").
int processNameMatch(const char *filter, const char *exePath);

// live subsystem (driver backed)
int  procflowStart(char *err, size_t errSize);
void procflowStop(void);
int  procflowRunning(void);
uint32_t procflowLookup(const void *packet, UINT len);   // pid or 0
int  procflowName(uint32_t pid, char *buf, size_t size);  // base exe name
