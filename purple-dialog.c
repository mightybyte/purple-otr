/*
 *  Off-the-Record Messaging plugin for pidgin
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

/* system headers */
#include <stdio.h>
#include <stdlib.h>

/* gcrypt headers */
#include <gcrypt.h>

/* purple headers */
#include "plugin.h"
#include "version.h"
#include "notify.h"
#include "request.h"
#include "util.h"
#include "core.h"

#ifdef ENABLE_NLS
/* internationalisation headers */
#include <glib/gi18n-lib.h>
#endif

/* libotr headers */
#include <libotr/dh.h>
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/userstate.h>

/* purple-otr headers */
#include "otr-plugin.h"
#include "dialogs.h"
#include "purple-dialog.h"
#include "ui.h"
#include "otr-icons.h"

static int img_id_not_private = 0;
static int img_id_unverified = 0;
static int img_id_private = 0;
static int img_id_finished = 0;

/* Information used by the plugin that is specific to both the
 * application and connection. */
typedef struct dialog_context_data {
    void       *smp_secret_dialog;
    void       *smp_progress_dialog;
    double	smp_progress_value;
    char       *smp_progress_primary;
    gboolean	smp_progress_ok;
} SMPData;

static void close_progress_window(SMPData *smp_data)
{
    if (smp_data->smp_progress_dialog) {
	purple_notify_close(PURPLE_NOTIFY_MESSAGE, smp_data->smp_progress_dialog);
	smp_data->smp_progress_dialog = NULL;
	g_free(smp_data->smp_progress_primary);
	smp_data->smp_progress_primary = NULL;
    }
}

static void otrg_purple_dialog_free_smp_data(PurpleConversation *conv)
{
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    if (!smp_data) return;

    if (smp_data->smp_secret_dialog) {
	purple_request_close(PURPLE_REQUEST_FIELDS, smp_data->smp_secret_dialog);
	smp_data->smp_secret_dialog = NULL;
    }

    close_progress_window(smp_data);

    free(smp_data);

    g_hash_table_remove(conv->data, "otr-smpdata");
}

static void otrg_purple_dialog_add_smp_data(PurpleConversation *conv)
{
    SMPData *smp_data = malloc(sizeof(SMPData));
    smp_data->smp_secret_dialog = NULL;
    smp_data->smp_progress_dialog = NULL;
    smp_data->smp_progress_primary = NULL;
    smp_data->smp_progress_ok = FALSE;

    purple_conversation_set_data(conv, "otr-smpdata", smp_data);
}

/* Forward declarations for the benefit of smp_message_response_cb/redraw authvbox */
static void *create_smp_progress_dialog(ConnContext *context);

/* Called when a button is pressed on the "progress bar" smp dialog */
static void smp_progress_cancel_cb(void *data)
{
    ConnContext *context = data;
    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 0);
    SMPData *smp_data = NULL;

    if (conv) {
	gdouble frac;

	smp_data = purple_conversation_get_data(conv, "otr-smpdata");
	/* If we closed this ourselves, let it go */
	if (smp_data->smp_progress_ok) {
	    smp_data->smp_progress_ok = FALSE;
	    return;
	}
	frac = smp_data->smp_progress_value;
	if (frac != 0.0 && frac != 1.0) {
	    otrg_plugin_abort_smp(context);
	}
    }

    /* Clean up variables pointing to the destroyed objects */
    if (smp_data) {
	g_free(smp_data->smp_progress_primary);
	smp_data->smp_progress_dialog = NULL;
	smp_data->smp_progress_primary = NULL;
    }
}

static void smp_qanda_cb(void *data, PurpleRequestFields *fields)
{
    ConnContext *context = data;
    const char *secret, *question;
    size_t secret_len;
    gboolean responder;

    secret = purple_request_fields_get_string(fields, "answer");
    secret_len = strlen(secret);

    responder = purple_request_fields_get_bool(fields, "responder");
    if (responder) {
	otrg_plugin_continue_smp(context, (const unsigned char *)secret,
	    secret_len);
    } else {
	question = purple_request_fields_get_string(fields, "question");
	if (!question || question[0] == '\0')
	    return;
	/* pass user question here */
	otrg_plugin_start_smp(context, question,
	       (const unsigned char *)secret, secret_len);
    }
    create_smp_progress_dialog(context);
}

static void smp_qanda(ConnContext *context, char *question)
{
    char *primary, *secondary, *qlabel;
    PurpleRequestFields *request;
    PurpleRequestFieldGroup *group;
    PurpleRequestField *field;
    PurpleConversation *conv;

    if (question) {
        secondary =
	    _("Your buddy is attempting to determine if he or she is really "
		"talking to you, or if it's someone pretending to be you.  "
		"Your buddy has asked a question, indicated below.  "
		"To authenticate to your buddy, enter the answer and "
		"click OK.");
	qlabel = _("This is the question asked by your buddy:");
    } else {
        secondary =
	    _("To authenticate using a question, pick a question whose "
	    "answer is known only to you and your buddy.  Enter this "
	    "question and this answer, then wait for your buddy to "
	    "enter the answer too.  If the answers "
	    "don't match, then you may be talking to an imposter.");
        qlabel = _("Enter question here:");
    }

    request = purple_request_fields_new();
    group = purple_request_field_group_new(NULL);
    field = purple_request_field_string_new("question", qlabel,
	question, FALSE);
    if (question)
	purple_request_field_string_set_editable(field, FALSE);
    else
	purple_request_field_set_required(field, TRUE);
    purple_request_field_group_add_field(group, field);

    field = purple_request_field_string_new("answer",
	_("Enter secret answer here (case sensitive):"),
	NULL, FALSE);
    purple_request_field_set_required(field, TRUE);
    purple_request_field_group_add_field(group, field);

    field = purple_request_field_bool_new("responder", "", question != NULL);
    purple_request_field_set_visible(field, FALSE);
    purple_request_field_group_add_field(group, field);

    purple_request_fields_add_group(request, group);

    if (question) {
        primary = g_strdup_printf(_("Authentication from %s"),
            context->username);
    } else {
        primary = g_strdup_printf(_("Authenticate %s"),
            context->username);
    }
    conv = otrg_plugin_context_to_conv(context, 0);
    purple_request_fields(otrg_plugin_handle,
	_("Authenticate Buddy"), primary, secondary, request,
	_("Authenticate"), G_CALLBACK(smp_qanda_cb),
	_("Cancel"), NULL,
	purple_conversation_get_account(conv),
	context->username, conv, context);

    g_free(primary);
}

static void smp_shared_cb(void *data, PurpleRequestFields *fields)
{
    ConnContext *context = data;
    const char *secret;
    size_t secret_len;
    gboolean responder;

    secret = purple_request_fields_get_string(fields, "secret");
    secret_len = strlen(secret);

    responder = purple_request_fields_get_bool(fields, "responder");

    if (responder) {
	otrg_plugin_continue_smp(context, (const unsigned char *)secret,
	    secret_len);
    } else {
	otrg_plugin_start_smp(context, NULL,
	       (const unsigned char *)secret, secret_len);
    }
    create_smp_progress_dialog(context);
}

static void smp_shared(ConnContext *context, gboolean responder)
{
    char *primary, *secondary, *qlabel;
    PurpleRequestFields *request;
    PurpleRequestFieldGroup *group;
    PurpleRequestField *field;
    PurpleConversation *conv;

    request = purple_request_fields_new();
    group = purple_request_field_group_new(NULL);

    field = purple_request_field_string_new("secret",
	_("Enter secret here:"), NULL, FALSE);
    purple_request_field_set_required(field, TRUE);
    purple_request_field_group_add_field(group, field);

    field = purple_request_field_bool_new("responder", "", responder);
    purple_request_field_set_visible(field, FALSE);
    purple_request_field_group_add_field(group, field);

    purple_request_fields_add_group(request, group);

    if (responder) {
        primary = g_strdup_printf(_("Authentication from %s"),
            context->username);
    } else {
        primary = g_strdup_printf(_("Authenticate %s"),
            context->username);
    }
    conv = otrg_plugin_context_to_conv(context, 0);
    purple_request_fields(otrg_plugin_handle,
	_("Authenticate Buddy"), primary,
        _("To authenticate, pick a secret known "
            "only to you and your buddy.  Enter this secret, then "
            "wait for your buddy to enter it too.  If the secrets "
            "don't match, then you may be talking to an imposter."),
	request,
	_("Authenticate"), G_CALLBACK(smp_shared_cb),
	_("Cancel"), NULL,
	purple_conversation_get_account(conv),
	context->username, conv, context);

    g_free(primary);
}

static void close_smp_window(PurpleConversation *conv)
{
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    if (smp_data && smp_data->smp_secret_dialog) {
	purple_request_close(PURPLE_REQUEST_FIELDS, smp_data->smp_secret_dialog);
    }
}

static void *create_smp_progress_dialog(ConnContext *context)
{
    PurpleConversation *conv;
    SMPData *smp_data;
    char *primary;
    void *handle;

    conv = otrg_plugin_context_to_conv(context, 0);
    smp_data = purple_conversation_get_data(conv, "otr-smpdata");

    primary = g_strdup_printf(context->smstate->received_question ?
		   _("Authenticating to %s") :
		   _("Authenticating %s") , context->username);
    handle = purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO,
	    context->smstate->received_question ?
            /* Translators: you are asked to authenticate yourself */
	    _("Authenticating to Buddy") :
            /* Translators: you asked your buddy to authenticate him/herself */
	    _("Authenticating Buddy"),
		primary,
	    _("Waiting for buddy..."),
	    smp_progress_cancel_cb, context);

    if (smp_data) {
	smp_data->smp_progress_dialog = handle;
	smp_data->smp_progress_value = 0.1;
	smp_data->smp_progress_primary = primary;
    } else {
	g_free(primary);
    }

    return handle;
}

/* This is just like purple_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
static void otrg_purple_dialog_notify_message(PurpleNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    purple_notify_message(otrg_plugin_handle, type, title,
	primary, secondary, NULL, NULL);
}

/* Put up a Please Wait dialog, with the "OK" button desensitized.
 * Return a handle that must eventually be passed to
 * otrg_dialog_private_key_wait_done. */
static OtrgDialogWaitHandle otrg_purple_dialog_private_key_wait_start(
	const char *account, const char *protocol)
{
    PurplePlugin *p;
    const char *title = _("Generating private key");
    const char *primary = _("Please wait");
    char *secondary;
    const char *protocol_print;
    void *handle;

    p = purple_find_prpl(protocol);
    protocol_print = (p ? p->info->name : _("Unknown"));

    /* Create the Please Wait... dialog */
    secondary = g_strdup_printf(_("Generating private key for %s (%s)..."),
	    account, protocol_print);

    handle = purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO,
	title, primary, secondary, NULL, NULL);

    g_free(secondary);

    return (OtrgDialogWaitHandle)handle;
}

static int otrg_purple_dialog_display_otr_message(const char *accountname,
	const char *protocol, const char *username, const char *msg)
{
    /* See if there's a conversation window we can put this in. */
    PurpleAccount *account;
    PurpleConversation *conv;

    account = purple_accounts_find(accountname, protocol);
    if (!account) return -1;

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, username, account);
    if (!conv) return -1;

    purple_conversation_write(conv, NULL, msg, PURPLE_MESSAGE_SYSTEM, time(NULL));

    return 0;
}

/* End a Please Wait dialog. */
static void otrg_purple_dialog_private_key_wait_done(OtrgDialogWaitHandle handle)
{
    purple_notify_close(PURPLE_NOTIFY_MSG_INFO, (void *)handle);
}

/* Inform the user that an unknown fingerprint was received. */
static void otrg_purple_dialog_unknown_fingerprint(OtrlUserState us,
	const char *accountname, const char *protocol, const char *who,
	unsigned char fingerprint[20])
{
    PurpleConversation *conv;
    char *buf;
    ConnContext *context;
    int seenbefore = FALSE;

    /* Figure out if this is the first fingerprint we've seen for this
     * user. */
    context = otrl_context_find(us, who, accountname, protocol, FALSE,
	    NULL, NULL, NULL);
    if (context) {
	Fingerprint *fp = context->fingerprint_root.next;
	while(fp) {
	    if (memcmp(fingerprint, fp->fingerprint, 20)) {
		/* This is a previously seen fingerprint for this user,
		 * different from the one we were passed. */
		seenbefore = TRUE;
		break;
	    }
	    fp = fp->next;
	}
    }

    if (seenbefore) {
	buf = g_strdup_printf(_("%s is contacting you from an unrecognized "
		    "computer.  You should <a href=\"%s%s\">authenticate</a> "
		    "this buddy."), who, AUTHENTICATE_HELPURL, _("?lang=en"));
    } else {
	buf = g_strdup_printf(_("%s has not been authenticated yet.  You "
		    "should <a href=\"%s%s\">authenticate</a> this buddy."),
		who, AUTHENTICATE_HELPURL, _("?lang=en"));
    }

    conv = otrg_plugin_userinfo_to_conv(accountname, protocol, who, TRUE);

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

    g_free(buf);
}

static void dialog_update_label_conv(PurpleConversation *conv, TrustLevel level)
{
    if (!conv) return;
    purple_conversation_set_data(conv, "otr-level", GINT_TO_POINTER(level));
    purple_conversation_update(conv, PURPLE_CONV_UPDATE_FEATURES);
}

static void dialog_update_label(PurpleConversation *conv, ConnContext *context)
{
    TrustLevel prev, level = otrg_plugin_context_to_trust(context);
    char *buf, *status = "";
    int id;

    prev = GPOINTER_TO_INT(purple_conversation_get_data(conv, "otr-level"));
    dialog_update_label_conv(conv, level);
    if (prev == level)
	return;

    buf = _("<img id=\"%d\"> The privacy status of the current conversation is now: <a href=\"%s%s\">%s</a>");

    switch(level) {
        case TRUST_NOT_PRIVATE:
            status = _("Not Private");
	    id = img_id_not_private;
            break;
        case TRUST_UNVERIFIED:
            status = _("Unverified");
	    id = img_id_unverified;
            break;
        case TRUST_PRIVATE:
            status = _("Private");
	    id = img_id_private;
            break;
        case TRUST_FINISHED:
            status = _("Finished");
	    id = img_id_finished;
            break;
    }

    buf = g_strdup_printf(buf, id, LEVELS_HELPURL, _("?lang=en"), status);

    /* Write a new message indicating the level change. */
    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

    g_free(buf);
}

struct vrfy_fingerprint_data {
    Fingerprint *fprint;   /* You can use this pointer right away, but
			      you can't rely on it sticking around for a
			      while.  Use the copied pieces below
			      instead. */
    char *accountname, *username, *protocol;
    unsigned char fingerprint[20];
};

static void vrfy_fingerprint_data_free(struct vrfy_fingerprint_data *vfd)
{
    free(vfd->accountname);
    free(vfd->username);
    free(vfd->protocol);
    free(vfd);
}

static struct vrfy_fingerprint_data* vrfy_fingerprint_data_new(
	Fingerprint *fprint)
{
    struct vrfy_fingerprint_data *vfd;
    ConnContext *context = fprint->context;

    vfd = malloc(sizeof(*vfd));
    vfd->fprint = fprint;
    vfd->accountname = strdup(context->accountname);
    vfd->username = strdup(context->username);
    vfd->protocol = strdup(context->protocol);
    memmove(vfd->fingerprint, fprint->fingerprint, 20);

    return vfd;
}

static void verify_cb(void *data, PurpleRequestFields *fields)
{
    struct vrfy_fingerprint_data *vfd = data;
    ConnContext *context = otrl_context_find(otrg_plugin_userstate,
	    vfd->username, vfd->accountname, vfd->protocol, 0, NULL,
	    NULL, NULL);
    Fingerprint *fprint;
    gboolean oldtrust, trust;

    if (context == NULL) return;

    fprint = otrl_context_find_fingerprint(context, vfd->fingerprint,
	    0, NULL);

    if (fprint == NULL) return;

    oldtrust = (fprint->trust && fprint->trust[0]);
    trust = purple_request_fields_get_bool(fields, "checked");

    /* See if anything's changed */
    if (trust != oldtrust) {
	PurpleConversation *conv;
	otrl_context_set_trust(fprint, trust ? "verified" : "");
	/* Write the new info to disk, redraw the ui, and redraw the
	 * OTR buttons. */
	otrg_plugin_write_fingerprints();
	otrg_ui_update_keylist();
	otrg_dialog_resensitize_all();
	conv = otrg_plugin_context_to_conv(context, 0);
	if (conv)
	     dialog_update_label(conv, context);
    }
}

static void verify_cancel(void *vfd, PurpleRequestFields *fields)
{
    vrfy_fingerprint_data_free(vfd);
}

static void otrg_purple_dialog_verify_fingerprint(Fingerprint *fprint)
{
    PurpleRequestFields *request;
    PurpleRequestFieldGroup *group;
    PurpleRequestField *field;
    PurpleAccount *account;
    char our_hash[45], their_hash[45];
    char *primary;
    char *secondary;
    char *label;
    struct vrfy_fingerprint_data *vfd;
    ConnContext *context;
    PurplePlugin *p;
    char *proto_name;
    gboolean oldtrust;

    if (fprint == NULL) return;
    if (fprint->fingerprint == NULL) return;
    context = fprint->context;
    if (context == NULL) return;

    primary = g_strdup_printf(_("Verify fingerprint for %s"),
	    context->username);
    vfd = vrfy_fingerprint_data_new(fprint);

    strcpy(our_hash, _("[none]"));
    otrl_privkey_fingerprint(otrg_plugin_userstate, our_hash,
	    context->accountname, context->protocol);

    otrl_privkey_hash_to_human(their_hash, fprint->fingerprint);

    p = purple_find_prpl(context->protocol);
    proto_name = (p && p->info->name) ? p->info->name : _("Unknown");
    secondary = g_strdup_printf(_("%s %s\n\n"
		"Fingerprint for you, %s (%s):\n%s\n\n"
		"Purported fingerprint for %s:\n%s\n"),
	    _("To verify the fingerprint, contact your buddy via some "
	    "*OTHER* authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your fingerprint "
	    "to the other."),
	    _("If everything matches up, you should check the checkbox below."),
	    context->accountname, proto_name, our_hash,
	    context->username, their_hash);

    account = purple_accounts_find(context->accountname, context->protocol);

    group = purple_request_field_group_new(NULL);
    label = g_strdup_printf(_("I have verified that this is in fact the "
	"correct fingerprint for %s."), context->username);
    oldtrust = (fprint->trust && fprint->trust[0]);
    field = purple_request_field_bool_new("checked", label, oldtrust);
    g_free(label);
	purple_request_field_group_add_field(group, field);
    request = purple_request_fields_new();
    purple_request_fields_add_group(request, group);

    purple_request_fields(otrg_plugin_handle,
	    _("Verify fingerprint"), primary, secondary, request,
	    _("Verify"), G_CALLBACK(verify_cb),
	    _("Cancel"), G_CALLBACK(verify_cancel),
	    account, context->username, NULL, vfd);

    g_free(primary);
    g_free(secondary);
}

static void choose_cb(void *vc, int which)
{
    ConnContext *context = vc;
    switch(which) {
    case 0: /* Question and answer */
	smp_qanda(context, NULL);
	break;
    case 1: /* Shared secret */
	smp_shared(context, FALSE);
	break;
    case 2: /* Manual fingerprint verification */
	otrg_purple_dialog_verify_fingerprint(context->active_fingerprint);
	break;
    case 3: /* Help */ {
	char *helpurl = g_strdup_printf("%s%s",
		AUTHENTICATE_HELPURL, _("?lang=en"));
	purple_notify_uri(otrg_plugin_handle, helpurl);
	g_free(helpurl);
	}
	break;
    }
}

/* Create the SMP dialog.  responder is true if this is called in
 * response to someone else's run of SMP. */
static void otrg_purple_dialog_socialist_millionaires(ConnContext *context,
	char *question, gboolean responder)
{
    char *primary;

    if (context == NULL) return;

    if (responder && question) {
        primary = g_strdup_printf(_("Authentication from %s"),
            context->username);
    } else {
        primary = g_strdup_printf(_("Authenticate %s"),
            context->username);
    }

    if (!responder) {
	PurpleConversation *conv = otrg_plugin_context_to_conv(context, 0);
	PurpleAccount *account = purple_conversation_get_account(conv);
	purple_request_choice(otrg_plugin_handle,
	    _("Authenticate Buddy"), primary,
	    _("Authenticating a buddy helps ensure that the person "
	    "you are talking to is who he or she claims to be."
	    "\n\n"
	    "How would you like to authenticate your buddy?"),
	    0,
		_("OK"), G_CALLBACK(choose_cb),
		_("Cancel"), NULL,
	    account, context->username, conv, context,
	    _("Question and answer"), 0,
	    _("Shared secret"), 1,
	    _("Manual fingerprint verification"), 2,
	    _("Help"), 3,
		NULL);
    } else {
	if (question) {
	    smp_qanda(context, question);
	} else {
	    smp_shared(context, TRUE);
	}
    }

    g_free(primary);
}

/* Call this to update the status of an ongoing socialist millionaires
 * protocol.  Progress_level is a percentage, from 0.0 (aborted) to
 * 1.0 (complete).  Any other value represents an intermediate state. */
static void otrg_purple_dialog_update_smp(ConnContext *context,
	double progress_level)
{
    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 0);
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    char *title, *primary, *secondary;

    if (!smp_data) return;

    smp_data->smp_progress_value = progress_level;
    /* tell close handler to ignore this close */
    smp_data->smp_progress_ok = TRUE;

    title =  context->smstate->received_question ?
            /* Translators: you are asked to authenticate yourself */
	    _("Authenticating to Buddy") :
            /* Translators: you asked your buddy to authenticate him/herself */
	    _("Authenticating Buddy");
    primary = smp_data->smp_progress_primary;

    /* If the counter is reset to absolute zero, the protocol has aborted */
    if (progress_level == 0.0) {
	purple_notify_close(PURPLE_NOTIFY_MESSAGE, smp_data->smp_progress_dialog);
	smp_data->smp_progress_dialog = NULL;
	smp_data->smp_progress_primary = NULL;
	purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_ERROR,
	    title, primary,
	    _("An error occurred during authentication."),
	    NULL, NULL);
	g_free(primary);
	return;
    } else if (progress_level == 1.0) {
	/* If the counter reaches 1.0, the protocol is complete */
        if (context->smstate->sm_prog_state == OTRL_SMP_PROG_SUCCEEDED) {
	    if (context->active_fingerprint->trust &&
		    context->active_fingerprint->trust[0]) {
		secondary = _("Authentication successful.");
	    } else {
		secondary = _("Your buddy has successfully authenticated you.  "
			    "You may want to authenticate your buddy as "
			    "well by asking your own question.");
	    }
        } else {
	    secondary = _("Authentication failed.");
	}
	purple_notify_close(PURPLE_NOTIFY_MESSAGE, smp_data->smp_progress_dialog);
	smp_data->smp_progress_dialog = NULL;
	smp_data->smp_progress_primary = NULL;
	purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO,
	    title, primary, secondary, NULL, NULL);
	g_free(primary);
    } else {
	secondary = g_strdup_printf(_("Authentication %d%% complete"),
	    (int)(progress_level * 100));
	purple_notify_close(PURPLE_NOTIFY_MESSAGE, smp_data->smp_progress_dialog);
	smp_data->smp_progress_dialog = purple_notify_message(otrg_plugin_handle,
	    PURPLE_NOTIFY_MSG_INFO, title, primary, secondary,
	    smp_progress_cancel_cb, context);
	g_free(secondary);
    }
}

/* Call this when a context transitions to ENCRYPTED. */
static void otrg_purple_dialog_connected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;
    char *format_buf;
    TrustLevel level;
    OtrgUiPrefs prefs;
    int id;

    conv = otrg_plugin_context_to_conv(context, TRUE);
    level = otrg_plugin_context_to_trust(context);

    otrg_ui_get_prefs(&prefs, purple_conversation_get_account(conv),
	    context->username);
    if (prefs.avoid_logging_otr) {
	purple_conversation_set_logging(conv, FALSE);
    }

    switch(level) {
       case TRUST_PRIVATE:
           format_buf = g_strdup(_("<img id=\"%d\"> Private conversation with %s started.%s"));
	   id = img_id_private;
           break;

       case TRUST_UNVERIFIED:
           format_buf = g_strdup_printf(_("<img id=\"%%d\"> <a href=\"%s%s\">Unverified</a> "
                       "conversation with %%s started.%%s"),
                       UNVERIFIED_HELPURL, _("?lang=en"));
	   id = img_id_unverified;
           break;

       default:
           /* This last case should never happen, since we know
            * we're in ENCRYPTED. */
           format_buf = g_strdup(_("<img id=\"%d\"> Not private conversation with %s "
                       "started.%s"));
	   id = img_id_not_private;
           break;
    }
    buf = g_strdup_printf(format_buf, id,
		purple_conversation_get_name(conv),
		context->protocol_version == 1 ? _("  Warning: using old "
		    "protocol version 1.") : "");

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

    g_free(buf);
    g_free(format_buf);

    dialog_update_label_conv(conv, level);
}

/* Call this when a context transitions to PLAINTEXT. */
static void otrg_purple_dialog_disconnected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;
    OtrgUiPrefs prefs;

    conv = otrg_plugin_context_to_conv(context, 1);

    buf = g_strdup_printf(_("<img id=\"%d\"> Private conversation with %s ended."),
	    img_id_not_private, purple_conversation_get_name(conv));

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

    g_free(buf);

    otrg_ui_get_prefs(&prefs, purple_conversation_get_account(conv),
	    context->username);
    if (prefs.avoid_logging_otr) {
	if (purple_prefs_get_bool("/purple/logging/log_ims"))
	{
	    purple_conversation_set_logging(conv, TRUE);
	}
    }

    dialog_update_label_conv(conv, TRUST_NOT_PRIVATE);
    close_smp_window(conv);
}

/* Call this if the remote user terminates his end of an ENCRYPTED
 * connection, and lets us know. */
static void otrg_purple_dialog_finished(const char *accountname,
	const char *protocol, const char *username)
{
    /* See if there's a conversation window we can put this in. */
    PurpleAccount *account;
    PurpleConversation *conv;
    char *buf;

    account = purple_accounts_find(accountname, protocol);
    if (!account) return;

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
	    username, account);
    if (!conv) return;

    buf = g_strdup_printf(_("<img id=\"%d\"> %s has ended his/her private conversation with "
		"you; you should do the same."),
	    img_id_finished, purple_conversation_get_name(conv));

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

    g_free(buf);

    dialog_update_label_conv(conv, TRUST_FINISHED);
    close_smp_window(conv);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
static void otrg_purple_dialog_stillconnected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;
    char *format_buf;
    TrustLevel level;

    conv = otrg_plugin_context_to_conv(context, 1);
    level = otrg_plugin_context_to_trust(context);

    switch(level) {
       case TRUST_PRIVATE:
           format_buf = g_strdup(_("Successfully refreshed the private "
                       "conversation with %s.%s"));
           break;

       case TRUST_UNVERIFIED:
           format_buf = g_strdup_printf(_("Successfully refreshed the "
                       "<a href=\"%s%s\">unverified</a> conversation with "
                       "%%s.%%s"),
                       UNVERIFIED_HELPURL, _("?lang=en"));
           break;

       default:
           /* This last case should never happen, since we know
            * we're in ENCRYPTED. */
           format_buf = g_strdup(_("Successfully refreshed the not private "
                       "conversation with %s.%s"));
           break;
    }

    buf = g_strdup_printf(format_buf,
		purple_conversation_get_name(conv),
		context->protocol_version == 1 ? _("  Warning: using old "
		    "protocol version 1.") : "");

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

    g_free(buf);
    g_free(format_buf);

    dialog_update_label_conv(conv, level);
}

static void menu_whatsthis(void *widget, gpointer data)
{
    char *uri = g_strdup_printf("%s%s", LEVELS_HELPURL, _("?lang=en"));
    purple_notify_uri(otrg_plugin_handle, uri);
    g_free(uri);
}

/* If the conversation gets destroyed on us, clean up the data we stored
 * pointing to it. */
static void conversation_destroyed(PurpleConversation *conv, void *data)
{
    g_hash_table_remove(conv->data, "otr-level");
    otrg_purple_dialog_free_smp_data(conv);
}

/* Set up the per-conversation information display */
static void otrg_purple_dialog_new_conv(PurpleConversation *conv)
{
    otrg_purple_dialog_add_smp_data(conv);
}

/* Remove the per-conversation information display */
static void otrg_purple_dialog_remove_conv(PurpleConversation *conv)
{
    conversation_destroyed(conv, NULL);
}

/* Set all OTR buttons to "sensitive" or "insensitive" as appropriate.
 * Call this when accounts are logged in or out. */
static void otrg_purple_dialog_resensitize_all(void)
{
	/* nothing to do */
}

static void unref_img_by_id(int *id)
{
    if (id && *id > 0) {
        purple_imgstore_unref_by_id(*id);
	*id = -1;
    }
}

static void dialog_quitting(void)
{
    /* We need to do this by catching the quitting signal, because
     * purple (mistakenly?) frees up all data structures, including
     * the imgstore, *before* calling the unload() method of the
     * plugins. */
    unref_img_by_id(&img_id_not_private);
    unref_img_by_id(&img_id_unverified);
    unref_img_by_id(&img_id_private);
    unref_img_by_id(&img_id_finished);
}

/* Initialize the OTR dialog subsystem */
static void otrg_purple_dialog_init(void)
{
    img_id_not_private = purple_imgstore_add_with_id(
	    g_memdup(not_private_png, sizeof(not_private_png)),
	    sizeof(not_private_png), "");

    img_id_unverified = purple_imgstore_add_with_id(
	    g_memdup(unverified_png, sizeof(unverified_png)),
	    sizeof(unverified_png), "");

    img_id_private = purple_imgstore_add_with_id(
	    g_memdup(private_png, sizeof(private_png)),
	    sizeof(private_png), "");

    img_id_finished = purple_imgstore_add_with_id(
	    g_memdup(finished_png, sizeof(finished_png)),
	    sizeof(finished_png), "");

    purple_signal_connect(purple_conversations_get_handle(),
	    "deleting-conversation", otrg_plugin_handle,
	    PURPLE_CALLBACK(conversation_destroyed), NULL);

    purple_signal_connect(purple_get_core(),
	"quitting", otrg_plugin_handle, PURPLE_CALLBACK(dialog_quitting),
	NULL);
}

/* Deinitialize the OTR dialog subsystem */
static void otrg_purple_dialog_cleanup(void)
{
    purple_signal_disconnect(purple_get_core(), "quitting",
	    otrg_plugin_handle, PURPLE_CALLBACK(dialog_quitting));

    purple_signal_disconnect(purple_conversations_get_handle(),
	    "deleting-conversation", otrg_plugin_handle,
	    PURPLE_CALLBACK(conversation_destroyed));

    /* If we're quitting, the imgstore will already have been destroyed
     * by purple, but we should have already called dialog_quitting(),
     * so the img_id_* should be -1, and all should be OK. */
    unref_img_by_id(&img_id_not_private);
    unref_img_by_id(&img_id_unverified);
    unref_img_by_id(&img_id_private);
    unref_img_by_id(&img_id_finished);
}

static const OtrgDialogUiOps purple_dialog_ui_ops = {
    otrg_purple_dialog_init,
    otrg_purple_dialog_cleanup,
    otrg_purple_dialog_notify_message,
    otrg_purple_dialog_display_otr_message,
    otrg_purple_dialog_private_key_wait_start,
    otrg_purple_dialog_private_key_wait_done,
    otrg_purple_dialog_unknown_fingerprint,
    otrg_purple_dialog_verify_fingerprint,
    otrg_purple_dialog_socialist_millionaires,
    otrg_purple_dialog_update_smp,
    otrg_purple_dialog_connected,
    otrg_purple_dialog_disconnected,
    otrg_purple_dialog_stillconnected,
    otrg_purple_dialog_finished,
    otrg_purple_dialog_resensitize_all,
    otrg_purple_dialog_new_conv,
    otrg_purple_dialog_remove_conv
};

/* Get the Purple dialog UI ops */
const OtrgDialogUiOps *otrg_purple_dialog_get_ui_ops(void)
{
    return &purple_dialog_ui_ops;
}
