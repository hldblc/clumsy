#include "profiles.h"
#include <stddef.h>

// Each profile first clears the common impairments, then dials in its own.
// Values are rough but representative; tweak to taste. "lag.time" and friends
// accept per-direction "down/up" via the in/out syntax.
#define RESET "lag=off drop=off throttle=off duplicate=off ood=off tamper=off " \
              "reset=off bandwidth=off tcp=off outage=off fragment=off"

typedef struct { const char *name; const char *text; } Profile;

static const Profile profiles[] = {
    { "(clear all)",
      RESET },
    { "Good Wi-Fi",
      RESET " lag=on lag.time=10 lag.jitter=5 lag.dist=uniform" },
    { "Lossy Wi-Fi",
      RESET " lag=on lag.time=25 lag.jitter=25 lag.dist=normal"
            " drop=on drop.chance=2 drop.burst=on drop.burstlen=4" },
    { "4G / LTE",
      RESET " lag=on lag.time=45/55 lag.jitter=20 lag.dist=normal"
            " bandwidth=on bandwidth.limit=5000/1500 bandwidth.mode=shape bandwidth.queue=150" },
    { "3G",
      RESET " lag=on lag.time=150/200 lag.jitter=60 lag.dist=spiky"
            " drop=on drop.chance=1"
            " bandwidth=on bandwidth.limit=384/128 bandwidth.mode=shape bandwidth.queue=400" },
    { "Congested DSL (bufferbloat)",
      RESET " lag=on lag.time=40 lag.jitter=10 lag.dist=normal"
            " bandwidth=on bandwidth.limit=1500/256 bandwidth.mode=shape bandwidth.queue=1000 bandwidth.full=tail-drop" },
    { "Satellite",
      RESET " lag=on lag.time=600 lag.jitter=40 lag.dist=normal"
            " drop=on drop.chance=1"
            " bandwidth=on bandwidth.limit=2000/500 bandwidth.mode=shape bandwidth.queue=300" },
    { "Intercontinental fiber",
      RESET " lag=on lag.time=160 lag.jitter=8 lag.dist=normal" },
    { "Flaky link (flapping)",
      RESET " outage=on outage.mode=random outage.up=8000 outage.down=1500"
            " lag=on lag.time=60 lag.jitter=30 lag.dist=normal" },
    { "Heavy loss",
      RESET " drop=on drop.chance=10 drop.burst=on drop.burstlen=8 drop.burstloss=100" },
};

int profileCount(void) {
    return (int)(sizeof(profiles) / sizeof(profiles[0]));
}

const char *profileName(int i) {
    return (i >= 0 && i < profileCount()) ? profiles[i].name : NULL;
}

const char *profileText(int i) {
    return (i >= 0 && i < profileCount()) ? profiles[i].text : NULL;
}
