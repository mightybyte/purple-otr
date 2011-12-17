/*
 *  Off-the-Record Messaging plugin for libpurple
 *  Copyright (C) 2011 Howard Chu <hyc@symas.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* config.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* libgcrypt headers */
#include <gcrypt.h>

/* libotr headers */
#include <libotr/privkey.h>

/* purple headers */
#include "util.h"
#include "account.h"
#include "notify.h"
#include "request.h"

#ifdef ENABLE_NLS
/* internationalisation header */
#include <glib/gi18n-lib.h>
#endif

/* purple-otr headers */
#include "dialogs.h"
#include "ui.h"
#include "otr-plugin.h"

/* Call this function when the DSA key is updated; it will redraw the
 * UI, if visible. */
static void otrg_purple_ui_update_fingerprint(void)
{
    /* Nothing to do */
}

/* Update the keylist, if it's visible */
static void otrg_purple_ui_update_keylist(void)
{
    /* Nothing to do */
}

/* Load the global OTR prefs */
static void otrg_purple_ui_global_prefs_load(gboolean *enabledp,
	gboolean *automaticp, gboolean *onlyprivatep,
	gboolean *avoidloggingotrp)
{
    *enabledp = purple_prefs_get_bool(PREF_ENABLED);
    *automaticp = purple_prefs_get_bool(PREF_AUTO);
    *onlyprivatep = purple_prefs_get_bool(PREF_ONLYPRIV);
    *avoidloggingotrp = purple_prefs_get_bool(PREF_NOLOGOTR);
}

/* Load the OTR prefs for a particular buddy */
static void otrg_purple_ui_buddy_prefs_load(PurpleBuddy *buddy,
	gboolean *usedefaultp, gboolean *enabledp, gboolean *automaticp,
	gboolean *onlyprivatep, gboolean *avoidloggingotrp)
{
    PurpleBlistNode *node = &(buddy->node);

    *usedefaultp = ! purple_blist_node_get_bool(node, "OTR/overridedefault");

    if (*usedefaultp) {
	otrg_purple_ui_global_prefs_load(enabledp, automaticp, onlyprivatep,
		avoidloggingotrp);
    } else {
	*enabledp = purple_blist_node_get_bool(node, _PREF_ENABLED);
	*automaticp = purple_blist_node_get_bool(node, _PREF_AUTO);
	*onlyprivatep = purple_blist_node_get_bool(node, _PREF_ONLYPRIV);
	*avoidloggingotrp =
	    purple_blist_node_get_bool(node, _PREF_NOLOGOTR);
    }
}

/* Save the OTR prefs for a particular buddy */
static void otrg_purple_ui_buddy_prefs_save(PurpleBuddy *buddy,
	gboolean usedefault, gboolean enabled, gboolean automatic,
	gboolean onlyprivate, gboolean avoidloggingotr)
{
    PurpleBlistNode *node = &(buddy->node);

    purple_blist_node_set_bool(node, "OTR/overridedefault", !usedefault);
    purple_blist_node_set_bool(node, _PREF_ENABLED, enabled);
    purple_blist_node_set_bool(node, _PREF_AUTO, automatic);
    purple_blist_node_set_bool(node, _PREF_ONLYPRIV, onlyprivate);
    purple_blist_node_set_bool(node, _PREF_NOLOGOTR, avoidloggingotr);
}

static void config_buddy_cb(void *vbuddy, PurpleRequestFields *fields)
{
    PurpleBuddy *buddy = vbuddy;
    gboolean buddyusedefault, buddyenabled, buddyautomatic,
    	buddyonlyprivate, buddyavoidloggingotr;
    
    buddyusedefault = purple_request_fields_get_bool(fields, "default");
    buddyenabled = purple_request_fields_get_bool(fields, "enabled");
    buddyautomatic = purple_request_fields_get_bool(fields, "auto");
    buddyonlyprivate = purple_request_fields_get_bool(fields, "onlypriv");
    buddyavoidloggingotr = purple_request_fields_get_bool(fields, "nolog");

    /* Apply the changes */
    otrg_purple_ui_buddy_prefs_save(buddy,
    	buddyusedefault, buddyenabled, buddyautomatic,
    	buddyonlyprivate, buddyavoidloggingotr);
}

static void otrg_purple_ui_config_buddy(PurpleBuddy *buddy)
{
    PurpleRequestFields *request;
    PurpleRequestFieldGroup *group;
    PurpleRequestField *field;
    gboolean buddyusedefault, buddyenabled, buddyautomatic,
    	buddyonlyprivate, buddyavoidloggingotr;

    otrg_purple_ui_buddy_prefs_load(buddy, &buddyusedefault, &buddyenabled,
	    &buddyautomatic, &buddyonlyprivate, &buddyavoidloggingotr);

    group = purple_request_field_group_new(NULL);
    field = purple_request_field_bool_new("default", _("Use default "
	    "OTR settings for this buddy"), buddyusedefault);
    purple_request_field_group_add_field(group, field);
    request = purple_request_fields_new();
    purple_request_fields_add_group(request, group);

    group = purple_request_field_group_new(NULL);
    field = purple_request_field_bool_new("enabled", _("Enable private "
	    "messaging"), buddyenabled);
    purple_request_field_group_add_field(group, field);

    field = purple_request_field_bool_new("auto", _("Automatically "
	    "initiate private messaging"), buddyautomatic);
    purple_request_field_group_add_field(group, field);

    field = purple_request_field_bool_new("onlypriv", _("Require private "
	    "messaging"), buddyonlyprivate);
    purple_request_field_group_add_field(group, field);

    field = purple_request_field_bool_new("nolog", _("Don't log OTR conversations"),
	    buddyavoidloggingotr);
    purple_request_field_group_add_field(group, field);

    purple_request_fields_add_group(request, group);

    purple_request_fields(otrg_plugin_handle, _("OTR Settings"), NULL, NULL, request,
    	_("_Set"), G_CALLBACK(config_buddy_cb),
	_("_Cancel"), NULL,
	purple_buddy_get_account(buddy), purple_buddy_get_contact_alias(buddy),
	NULL, buddy);
}

/* Load the preferences for a particular account / username */
static void otrg_purple_ui_get_prefs(OtrgUiPrefs *prefsp, PurpleAccount *account,
	const char *name)
{
    PurpleBuddy *buddy;
    gboolean otrenabled, otrautomatic, otronlyprivate, otravoidloggingotr;
    gboolean buddyusedefault, buddyenabled, buddyautomatic, buddyonlyprivate,
	     buddyavoidloggingotr;

    prefsp->policy = OTRL_POLICY_DEFAULT;
    prefsp->avoid_logging_otr = FALSE;
    prefsp->show_otr_button = FALSE;
    
    /* Get the default policy */
    otrg_purple_ui_global_prefs_load(&otrenabled, &otrautomatic, &otronlyprivate,
	    &otravoidloggingotr);

    if (otrenabled) {
	if (otrautomatic) {
	    if (otronlyprivate) {
		prefsp->policy = OTRL_POLICY_ALWAYS;
	    } else {
		prefsp->policy = OTRL_POLICY_OPPORTUNISTIC;
	    }
	} else {
	    prefsp->policy = OTRL_POLICY_MANUAL;
	}
	prefsp->avoid_logging_otr = otravoidloggingotr;
    } else {
	prefsp->policy = OTRL_POLICY_NEVER;
    }

    buddy = purple_find_buddy(account, name);
    if (!buddy) return;

    /* Get the buddy-specific policy, if present */
    otrg_purple_ui_buddy_prefs_load(buddy, &buddyusedefault, &buddyenabled,
	    &buddyautomatic, &buddyonlyprivate, &buddyavoidloggingotr);

    if (buddyusedefault) return;

    if (buddyenabled) {
	if (buddyautomatic) {
	    if (buddyonlyprivate) {
		prefsp->policy = OTRL_POLICY_ALWAYS;
	    } else {
		prefsp->policy = OTRL_POLICY_OPPORTUNISTIC;
	    }
	} else {
	    prefsp->policy = OTRL_POLICY_MANUAL;
	}
	prefsp->avoid_logging_otr = buddyavoidloggingotr;
    } else {
	prefsp->policy = OTRL_POLICY_NEVER;
    }
}

/* Initialize the OTR UI subsystem */
static void otrg_purple_ui_init(void)
{
    /* Nothing to do */
}

/* Deinitialize the OTR UI subsystem */
static void otrg_purple_ui_cleanup(void)
{
    /* Nothing to do */
}

static const OtrgUiUiOps purple_ui_ui_ops = {
    otrg_purple_ui_init,
    otrg_purple_ui_cleanup,
    otrg_purple_ui_update_fingerprint,
    otrg_purple_ui_update_keylist,
    otrg_purple_ui_config_buddy,
    otrg_purple_ui_get_prefs
};

/* Get the Purple UI ops */
const OtrgUiUiOps *otrg_purple_ui_get_ui_ops(void)
{
    return &purple_ui_ui_ops;
}
