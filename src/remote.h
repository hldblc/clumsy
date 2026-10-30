// Opt-in remote control over a loopback HTTP + JSON API, so CI pipelines and
// test scripts can drive clumsy. Roadmap item 18.
//
// Bound to 127.0.0.1 only and gated by a token on every request. GET endpoints
// read shared state directly; mutations are marshalled to the UI thread through
// a caller-supplied enqueue callback (one text command per line) so they run
// where it is safe to touch the engine and widgets.
//
//   GET  /status                              engine + stats JSON
//   GET  /rules                               rules, modules and parameters JSON
//   POST /start                               begin filtering
//   POST /stop                                stop filtering
//   POST /profile?name=<profile>              apply a profile to the first rule
//   POST /set?rule=0&module=lag&param=time&value=100
//   POST /enable?rule=0&module=lag&on=1
//
// Auth: ?token=<t>, or "Authorization: Bearer <t>", or "X-Clumsy-Token: <t>".
#pragma once
#include "common.h"

// enqueue runs a one-line command on the UI thread (see remote.c for grammar).
int  remoteStart(int port, const char *token, void (*enqueue)(const char *cmd), char *err, size_t errSize);
void remoteStop(void);
int  remoteRunning(void);
int  remotePort(void);
const char *remoteToken(void);

// JSON builders (pure reads of shared state; unit tested)
int remoteBuildStatus(char *buf, size_t size);
int remoteBuildRules(char *buf, size_t size);

// apply one command line to the rule set / engine (called on the UI thread).
// Provided here so main.c and the tests share one implementation.
void remoteApplyCommand(const char *cmd);
