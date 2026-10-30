// Turn a hostname, IPv4 address or CIDR block into a WinDivert filter clause
// matching that endpoint in either direction. Roadmap item 15.
//
//   10.0.0.5        -> (ip.DstAddr == 10.0.0.5 or ip.SrcAddr == 10.0.0.5)
//   10.0.0.0/24     -> (ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.0.0.255) or ...
//   example.com     -> resolved A records, each as an == clause, OR-joined
#pragma once
#include "common.h"

// 1 and fills out on success; 0 with a message in out on failure.
int targetBuildClause(const char *input, char *out, size_t outSize);

// low-level: parse "a.b.c.d/n" into inclusive host-order bounds. 1 on success.
int targetParseCidr(const char *input, uint32_t *lo, uint32_t *hi);
