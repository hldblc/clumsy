// Binds module parameters to IUP widgets. The only place where the UI and the
// parameter tables meet; modules never touch IUP unless they need a custom control.
#pragma once
#include "iup.h"
#include "common.h"

#define UI_ATTR_INST  "_CLUMSY_INST"
#define UI_ATTR_PARAM "_CLUMSY_PARAM"

void uiInstallHooks(void);                                   // route programmatic changes to widgets
Ihandle *uiBindParam(ModuleInst *inst, const ParamDesc *p);  // widget bound to one parameter
Ihandle *uiBuildParamRow(ModuleInst *inst, int advanced);    // hbox of all (basic or advanced) params, NULL if none
void uiBuildModuleRow(ModuleInst *inst, Ihandle *parent);    // icon + enable toggle + controls (+ hidden advanced row)
void uiRefreshParam(ModuleInst *inst, const ParamDesc *p);
void uiRefreshEnabled(ModuleInst *inst);
void uiSetAdvancedVisible(int visible);                      // show/hide every module's advanced row
int  uiAdvancedVisible(void);
