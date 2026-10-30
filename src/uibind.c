#include <stdlib.h>
#include <stdio.h>
#include "uibind.h"
#include "engine.h"
#include "rules.h"

static int advancedVisible = 0;

static ModuleInst *instOf(Ihandle *ih) {
    return (ModuleInst *)IupGetAttribute(ih, UI_ATTR_INST);
}

static const ParamDesc *paramOf(Ihandle *ih) {
    return (const ParamDesc *)IupGetAttribute(ih, UI_ATTR_PARAM);
}

static int paramIndex(const ModuleInst *inst, const ParamDesc *p) {
    return (int)(p - inst->desc->params);
}

static void widgetShow(Ihandle *ih, const ParamDesc *p, int value) {
    char buf[32];
    switch (p->type) {
    case PT_BOOL:
        IupSetAttribute(ih, "VALUE", value ? "ON" : "OFF");
        break;
    case PT_ENUM:
        snprintf(buf, sizeof(buf), "%d", value + 1);
        IupStoreAttribute(ih, "VALUE", buf);
        break;
    default:
        paramFormat(p, value, buf, sizeof(buf));
        IupStoreAttribute(ih, "VALUE", buf);
        break;
    }
}

static int cbText(Ihandle *ih) {
    ModuleInst *inst = instOf(ih);
    const ParamDesc *p = paramOf(ih);
    const char *text = IupGetAttribute(ih, "VALUE");
    int v = 0, clamped;
    if (!paramParse(p, text ? text : "", &v)) v = 0;
    clamped = v < p->min ? p->min : (v > p->max ? p->max : v);
    paramSetInt(inst, p, -1, clamped);
    if (clamped != v && v != 0) {
        // normalize the text while keeping the caret at the end for continued typing
        widgetShow(ih, p, clamped);
        IupStoreAttribute(ih, "CARET", "10");
    }
    engineWake();
    return IUP_DEFAULT;
}

static int cbToggle(Ihandle *ih, int state) {
    paramSetInt(instOf(ih), paramOf(ih), -1, state);
    engineWake();
    return IUP_DEFAULT;
}

static int cbList(Ihandle *ih, char *text, int item, int state) {
    UNREFERENCED_PARAMETER(text);
    if (state == 1) {
        paramSetInt(instOf(ih), paramOf(ih), -1, item - 1);
        engineWake();
    }
    return IUP_DEFAULT;
}

Ihandle *uiBindParam(ModuleInst *inst, const ParamDesc *p) {
    Ihandle *ih;
    int idx = paramIndex(inst, p);
    switch (p->type) {
    case PT_BOOL:
        ih = IupToggle(p->label, NULL);
        IupSetCallback(ih, "ACTION", (Icallback)cbToggle);
        break;
    case PT_ENUM: {
        int i, n = paramEnumCount(p);
        char key[8], name[32];
        ih = IupList(NULL);
        IupSetAttribute(ih, "DROPDOWN", "YES");
        for (i = 0; i < n; ++i) {
            snprintf(key, sizeof(key), "%d", i + 1);
            paramEnumName(p, i, name, sizeof(name));
            IupStoreAttribute(ih, key, name);
        }
        IupSetCallback(ih, "ACTION", (Icallback)cbList);
        break;
    }
    default:
        ih = IupText(NULL);
        IupSetAttribute(ih, "VISIBLECOLUMNS", p->type == PT_INT32 ? "6" : "5");
        IupSetCallback(ih, "VALUECHANGED_CB", cbText);
        break;
    }
    IupSetAttribute(ih, UI_ATTR_INST, (char *)inst);
    IupSetAttribute(ih, UI_ATTR_PARAM, (char *)p);
    inst->widgets[idx] = ih;
    widgetShow(ih, p, paramGetInt(inst, p, -1));
    return ih;
}

Ihandle *uiBuildParamRow(ModuleInst *inst, int advanced) {
    Ihandle *box = IupHbox(NULL);
    int i, n = 0;
    for (i = 0; i < inst->desc->paramCount; ++i) {
        const ParamDesc *p = &inst->desc->params[i];
        if (p->flags & PF_HIDDEN) continue;
        if (((p->flags & PF_ADVANCED) != 0) != (advanced != 0)) continue;
        if (p->type != PT_BOOL) {
            char lbl[64];
            Ihandle *label = IupLabel(NULL);
            snprintf(lbl, sizeof(lbl), "%s:", p->label);
            IupSetStrAttribute(label, "TITLE", lbl);
            IupAppend(box, label);
        }
        IupAppend(box, uiBindParam(inst, p));
        ++n;
    }
    if (n == 0) {
        IupDestroy(box);
        return NULL;
    }
    IupSetAttribute(box, "ALIGNMENT", "ACENTER");
    IupSetAttribute(box, "GAP", "4");
    return box;
}

static int cbModuleToggle(Ihandle *ih, int state) {
    ModuleInst *inst = instOf(ih);
    atomicExch16(&inst->enabled, state ? 1 : 0);
    uiRefreshEnabled(inst);
    engineWake();
    return IUP_DEFAULT;
}

void uiBuildModuleRow(ModuleInst *inst, Ihandle *parent) {
    Ihandle *icon, *toggle, *controls, *row, *adv, *group;
    controls = inst->desc->setupUI ? inst->desc->setupUI(inst) : uiBuildParamRow(inst, 0);
    if (controls == NULL) controls = IupHbox(NULL);
    icon = IupLabel(NULL);
    IupSetAttribute(icon, "IMAGE", "none_icon");
    IupSetAttribute(icon, "PADDING", "4x");
    toggle = IupToggle(inst->desc->displayName, NULL);
    IupSetAttribute(toggle, UI_ATTR_INST, (char *)inst);
    IupSetCallback(toggle, "ACTION", (Icallback)cbModuleToggle);
    row = IupHbox(icon, toggle, IupFill(), controls, NULL);
    IupSetAttribute(row, "EXPAND", "HORIZONTAL");
    IupSetAttribute(row, "ALIGNMENT", "ACENTER");
    IupSetAttribute(controls, "ALIGNMENT", "ACENTER");
    IupSetAttribute(controls, "ACTIVE", "NO");
    IupSetAttribute(controls, "NCGAP", "4");

    adv = uiBuildParamRow(inst, 1);
    if (adv != NULL) {
        Ihandle *advRow = IupHbox(IupFill(), adv, NULL);
        IupSetAttribute(advRow, "EXPAND", "HORIZONTAL");
        IupSetAttribute(advRow, "ALIGNMENT", "ACENTER");
        IupSetAttribute(adv, "ACTIVE", "NO");
        IupSetAttribute(advRow, "VISIBLE", advancedVisible ? "YES" : "NO");
        IupSetAttribute(advRow, "FLOATING", advancedVisible ? "NO" : "IGNORE");
        group = IupVbox(row, advRow, NULL);
        IupSetAttribute(group, "EXPAND", "HORIZONTAL");
        inst->advanced = advRow;
        inst->controls = controls;
        // keep the advanced controls themselves reachable for ACTIVE toggling
        IupSetAttribute(advRow, "_CLUMSY_ADV", (char *)adv);
    } else {
        group = row;
        inst->advanced = NULL;
        inst->controls = controls;
    }
    IupAppend(parent, group);
    inst->icon = icon;
    inst->toggle = toggle;
}

void uiRefreshParam(ModuleInst *inst, const ParamDesc *p) {
    int idx = paramIndex(inst, p);
    Ihandle *ih;
    if (idx < 0 || idx >= inst->desc->paramCount) return;
    ih = inst->widgets[idx];
    if (ih == NULL) return;
    widgetShow(ih, p, paramGetInt(inst, p, -1));
}

void uiRefreshEnabled(ModuleInst *inst) {
    const char *active = inst->enabled ? "YES" : "NO";
    if (inst->toggle) IupSetAttribute(inst->toggle, "VALUE", inst->enabled ? "ON" : "OFF");
    if (inst->controls) IupSetAttribute(inst->controls, "ACTIVE", active);
    if (inst->advanced) {
        Ihandle *adv = (Ihandle *)IupGetAttribute(inst->advanced, "_CLUMSY_ADV");
        if (adv) IupSetAttribute(adv, "ACTIVE", active);
    }
}

void uiSetAdvancedVisible(int visible) {
    int i, j;
    advancedVisible = visible ? 1 : 0;
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        for (j = 0; j < r->moduleCount; ++j) {
            ModuleInst *m = r->modules[j];
            if (m->advanced == NULL) continue;
            IupSetAttribute(m->advanced, "FLOATING", advancedVisible ? "NO" : "IGNORE");
            IupSetAttribute(m->advanced, "VISIBLE", advancedVisible ? "YES" : "NO");
        }
    }
}

int uiAdvancedVisible(void) {
    return advancedVisible;
}

void uiInstallHooks(void) {
    paramUiRefreshHook = uiRefreshParam;
    moduleEnabledUiHook = uiRefreshEnabled;
}
