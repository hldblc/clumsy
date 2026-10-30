// pcapng packet logging. Records each packet as it is sent (post-impairment)
// with a per-packet comment naming the rule and what clumsy did to it, so a
// capture opens in Wireshark lined up with the impairment. Roadmap item 22.
//
// Link type is LINKTYPE_RAW (101): WinDivert packets begin at the IP header.
#pragma once
#include "common.h"

// block builders (pure; used by the writer and the unit tests). Return the
// number of bytes written, or 0 if it would not fit.
size_t pcapBuildHeaders(unsigned char *out, size_t cap);
size_t pcapBuildPacketBlock(unsigned char *out, size_t cap, const unsigned char *pkt,
                            UINT len, int64_t tsUs, const char *comment);

// build a human comment from the action flags (PN_FLAG_*) and rule name
void pcapActionComment(char *buf, size_t size, const char *ruleName, uint16_t flags, int outbound);

// live writer (processor thread writes; UI thread opens/closes)
int  pcapOpen(const char *path);
void pcapClose(void);
int  pcapIsOpen(void);
void pcapLogNode(const PacketNode *n, const char *ruleName);
