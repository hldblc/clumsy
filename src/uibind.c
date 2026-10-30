#include <stdlib.h>
#include <stdio.h>
#include "uibind.h"
#include "engine.h"
#include "rules.h"

#define UI_ATTR_DIR "_CLUMSY_DIR"

static int advancedVisible = 0;

static ModuleInst *instOf(Ihandle *ih) {
    return (ModuleInst *)IupGetAttribute(ih, UI_ATTR_INST);
}

static const ParamDesc *paramOf(Ihandle *ih) {
    return (const ParamDesc *)IupGetAttribute(ih, UI_ATTR_PARAM);
}

static int dirOf(Ihandle *ih) {
    const char *d = IupGetAttribute(ih, UI_ATTR_DIR);
    return d ? atoi(d) : -1;
}

static int paramIndex(const ModuleInst *inst, const ParamDesc *p) {
    return (int)(p - inst->desc->params);
}

// widget <- state
static void widgetShow(ModuleInst *inst, Ihandle *ih, const ParamDesc *p, int dir) {
    char buf[48];
    switch (p->type) {
    case PT_BOOL:
        IupSetAttribute(ih, "VALUE", paramGetInt(inst, p, -1) ? "ON" : "OFF");
        break;
    case PT_ENUM:
        snprintf(buf, sizeof(buf), "%d", paramGetInt(inst, p, -1) + 1);
        IupStoreAttribute(ih, "VALUE", buf);
        break;
    default:
        if (dir < 0) {
            paramFormatBoth(inst, p, buf, sizeof(buf));
        } else {
            paramFormat(p, paramGetInt(inst, p, dir), buf, sizeof(buf));
        }
        IupStoreAttribute(ih, "VALUE", buf);
        break;
    }
}

// refresh every widget bound to p except the one being edited
static void refreshWidgets(ModuleInst *inst, const ParamDesc *p, Ihandle *except) {
    int idx = paramIndex(inst, p), d;
    Ihandle *w;
    if (idx < 0 || idx >= inst->desc->paramCount) return;
    w = inst->widgets[idx];
    if (w && w != except) widgetShow(inst, w, p, -1);
    if (p->flags & PF_PERDIR) {
        for (d = 0; d < 2; ++d) {
            w = inst->widgetsDir[idx * 2 + d];
            if (w && w != except) widgetShow(inst, w, p, d);
        }
    }
}

static int cbText(Ihandle *ih) {
    ModuleInst *inst = instOf(ih);
    const ParamDesc *p = paramOf(ih);
    int dir = dirOf(ih);
    const char *text = IupGetAttribute(ih, "VALUE");
    int v = 0, clamped;
    if (text == NULL) text = "";
    if (dir < 0 && (p->flags & PF_PERDIR) && strchr(text, '/') != NULL) {
        // "in/out" sets both directions at once
        paramApplyText(inst, p, -1, text);
        engineWake();
        return IUP_DEFAULT;
    }
    if (!paramParse(p, text, &v)) v = 0;
    clamped = v < p->min ? p->min : (v > p->max ? p->max : v);
    paramSetInt(inst, p, dir, clamped);
    if (clamped != v && v != 0) {
        // normalize the text while keeping the caret at the end for continued typing
        widgetShow(inst, ih, p, dir);
        IupStoreAttribute(ih, "CARET", "10");
    }
    refreshWidgets(inst, p, ih);
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

static int cbAction(Ihandle *ih) {
    ModuleInst *inst = instOf(ih);
    if (inst->desc->action) inst->desc->action(inst);
    return IUP_DEFAULT;
}

static Ihandle *makeParamWidget(ModuleInst *inst, const ParamDesc *p, int dir) {
    Ihandle *ih;
    char dbuf[8];
    switch (p->type) {
    case PT_BOOL:
        ih = IupToggle(NULL, NULL);
        IupSetStrAttribute(ih, "TITLE", p->label);
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
    snprintf(dbuf, sizeof(dbuf), "%d", dir);
    IupStoreAttribute(ih, UI_ATTR_DIR, dbuf);
    widgetShow(inst, ih, p, dir);
    return ih;
}

Ihandle *uiBindParam(ModuleInst *inst, const ParamDesc *p) {
    Ihandle *ih = makeParamWidget(inst, p, -1);
    inst->widgets[paramIndex(inst, p)] = ih;
    return ih;
}

static Ihandle *bindParamDir(ModuleInst *inst, const ParamDesc *p, int dir) {
    Ihandle *ih = makeParamWidget(inst, p, dir);
    inst->widgetsDir[paramIndex(inst, p) * 2 + dir] = ih;
    return ih;
}

static void appendLabeled(Ihandle *box, const char *label, Ihandle *w) {
    Ihandle *l = IupLabel(NULL);
    IupSetStrAttribute(l, "TITLE", label);
    IupAppend(box, l);
    IupAppend(box, w);
}

Ihandle *uiBuildParamRow(ModuleInst *inst, int advanced) {
    Ihandle *box = IupHbox(NULL);
    int i, n = 0;
    char lbl[80];
    for (i = 0; i < inst->desc->paramCount; ++i) {
        const ParamDesc *p = &inst->desc->params[i];
        if (p->flags & PF_HIDDEN) continue;
        if (((p->flags & PF_ADVANCED) != 0) != (advanced != 0)) continue;
        if (p->type != PT_BOOL) {
            snprintf(lbl, sizeof(lbl), "%s:", p->label);
            appendLabeled(box, lbl, uiBindParam(inst, p));
        } else {
            IupAppend(box, uiBindParam(inst, p));
        }
        ++n;
    }
    if (advanced) {
        // separate inbound / outbound fields for every per-direction value
        for (i = 0; i < inst->desc->paramCount; ++i) {
            const ParamDesc *p = &inst->desc->params[i];
            if ((p->flags & PF_HIDDEN) || !(p->flags & PF_PERDIR)) continue;
            if (p->type == PT_BOOL || p->type == PT_ENUM) continue;
            snprintf(lbl, sizeof(lbl), "%s in:", p->label);
            appendLabeled(box, lbl, bindParamDir(inst, p, 0));
            appendLabeled(box, "out:", bindParamDir(inst, p, 1));
            ++n;
        }
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
    if (inst->desc->actionLabel != NULL) {
        Ihandle *btn = IupButton(NULL, NULL);
        Ihandle *first = IupGetChild(controls, 0);
        IupSetStrAttribute(btn, "TITLE", inst->desc->actionLabel);
        IupSetAttribute(btn, "PADDING", "4x");
        IupSetAttribute(btn, UI_ATTR_INST, (char *)inst);
        IupSetCallback(btn, "ACTION", cbAction);
        if (first) {
            IupInsert(controls, first, btn);
        } else {
            IupAppend(controls, btn);
        }
    }
    icon = IupLabel(NULL);
    IupSetAttribute(icon, "IMAGE", "none_icon");
    IupSetAttribute(icon, "PADDING", "4x");
    toggle = IupToggle(NULL, NULL);
    IupSetStrAttribute(toggle, "TITLE", inst->desc->displayName);
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
        IupSetAttribute(advRow, "_CLUMSY_ADV", (char *)adv);
        group = IupVbox(row, advRow, NULL);
        IupSetAttribute(group, "EXPAND", "HORIZONTAL");
        inst->advanced = advRow;
    } else {
        group = row;
        inst->advanced = NULL;
    }
    inst->controls = controls;
    IupAppend(parent, group);
    inst->icon = icon;
    inst->toggle = toggle;
}

void uiRefreshParam(ModuleInst *inst, const ParamDesc *p) {
    refreshWidgets(inst, p, NULL);
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
