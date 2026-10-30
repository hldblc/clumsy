// Built-in link profiles: named bundles of impairment settings applied to the
// current rule as a config fragment (see config.h). Item 6 on the roadmap.
#pragma once

int profileCount(void);
const char *profileName(int i);
const char *profileText(int i);   // config fragment, applied to one rule
