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
#include "pidginstock.h"
#include "notify.h"
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

#if 0
typedef struct {
    ConnContext *context;       /* The context used to fire library code */
    GtkEntry* question_entry;       /* The text entry field containing the user question */
    GtkEntry *entry;	        /* The text entry field containing the secret */
    int smp_type;               /* Whether the SMP type is based on question challenge (0) or shared secret (1) */
    gboolean responder;	        /* Whether or not this is the first side to give
			                       their secret */
} SmpResponsePair;

/* Information used by the plugin that is specific to both the
 * application and connection. */
typedef struct dialog_context_data {
    GtkWidget       *smp_secret_dialog;
    SmpResponsePair *smp_secret_smppair;
    GtkWidget       *smp_progress_dialog;
    GtkWidget       *smp_progress_bar;
    GtkWidget       *smp_progress_label;
} SMPData;

typedef struct {
    SmpResponsePair *smppair;
    GtkEntry        *one_way_entry;
    GtkEntry        *two_way_entry;
    GtkWidget       *notebook;
} AuthSignalData;

static void close_progress_window(SMPData *smp_data)
{
    if (smp_data->smp_progress_dialog) {
	gtk_dialog_response(GTK_DIALOG(smp_data->smp_progress_dialog),
		GTK_RESPONSE_REJECT);
    }
    smp_data->smp_progress_dialog = NULL;
    smp_data->smp_progress_bar = NULL;
    smp_data->smp_progress_label = NULL;
}

static void otrg_purple_dialog_free_smp_data(PurpleConversation *conv)
{
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    if (!smp_data) return;

    if (smp_data->smp_secret_dialog) {
	gtk_dialog_response(GTK_DIALOG(smp_data->smp_secret_dialog),
		GTK_RESPONSE_REJECT);
    }
    smp_data->smp_secret_dialog = NULL;
    smp_data->smp_secret_smppair = NULL;

    close_progress_window(smp_data);

    free(smp_data);

    g_hash_table_remove(conv->data, "otr-smpdata");
}

static void otrg_purple_dialog_add_smp_data(PurpleConversation *conv)
{
    SMPData *smp_data = malloc(sizeof(SMPData));
    smp_data->smp_secret_dialog = NULL;
    smp_data->smp_secret_smppair = NULL;
    smp_data->smp_progress_dialog = NULL;
    smp_data->smp_progress_bar = NULL;
    smp_data->smp_progress_label = NULL;

    purple_conversation_set_data(conv, "otr-smpdata", smp_data);
}

static GtkWidget *otr_icon(GtkWidget *image, TrustLevel level,
	gboolean sensitivity)
{
    GdkPixbuf *pixbuf = NULL;
    const guint8 *data = NULL;

    switch(level) {
	case TRUST_NOT_PRIVATE:
	    data = not_private_pixbuf;
	    break;
	case TRUST_UNVERIFIED:
	    data = unverified_pixbuf;
	    break;
	case TRUST_PRIVATE:
	    data = private_pixbuf;
	    break;
	case TRUST_FINISHED:
	    data = finished_pixbuf;
	    break;
    }

    pixbuf = gdk_pixbuf_new_from_inline(-1, data, FALSE, NULL);
    if (image) {
	gtk_image_set_from_pixbuf(GTK_IMAGE(image), pixbuf);
    } else {
	image = gtk_image_new_from_pixbuf(pixbuf);
    }
    gdk_pixbuf_unref(pixbuf);

    gtk_widget_set_sensitive (image, sensitivity);

    return image;
}

static void message_response_cb(GtkDialog *dialog, gint id, GtkWidget *widget)
{
    gtk_widget_destroy(GTK_WIDGET(widget));
}

/* Forward declarations for the benefit of smp_message_response_cb/redraw authvbox */
static void add_vrfy_fingerprint(GtkWidget *vbox, void *data);
static struct vrfy_fingerprint_data* vrfy_fingerprint_data_new(
	Fingerprint *fprint);
static void vrfy_fingerprint_destroyed(GtkWidget *w,
	struct vrfy_fingerprint_data *vfd);
static void conversation_switched ( PurpleConversation *conv, void * data );

static GtkWidget *create_smp_progress_dialog(GtkWindow *parent,
	ConnContext *context);

/* Called when a button is pressed on the "progress bar" smp dialog */
static void smp_progress_response_cb(GtkDialog *dialog, gint response,
	ConnContext *context)
{
    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 0);
    SMPData *smp_data = NULL;
    
    if (conv) {
	gdouble frac;

	smp_data = purple_conversation_get_data(conv, "otr-smpdata");
	frac = gtk_progress_bar_get_fraction(
		GTK_PROGRESS_BAR(smp_data->smp_progress_bar));

	if (frac != 0.0 && frac != 1.0 && response == GTK_RESPONSE_REJECT) {
	    otrg_plugin_abort_smp(context);
	}
    }
    /* In all cases, destroy the current window */
    gtk_widget_destroy(GTK_WIDGET(dialog));

    /* Clean up variables pointing to the destroyed objects */

    if (smp_data) {
	smp_data->smp_progress_bar = NULL;
	smp_data->smp_progress_label = NULL;
	smp_data->smp_progress_dialog = NULL;
    }
}

/* Called when a button is pressed on the "enter the secret" smp dialog
 * The data passed contains a pointer to the text entry field containing
 * the entered secret as well as the current context.
 */
static void smp_secret_response_cb(GtkDialog *dialog, gint response,
	AuthSignalData *auth_opt_data)
{
    ConnContext* context;
    PurpleConversation *conv;
    SMPData *smp_data;
    SmpResponsePair *smppair;

    if (!auth_opt_data) return;
    
    smppair = auth_opt_data->smppair;
    
    if (!smppair) return;

    context = smppair->context;

    if (response == GTK_RESPONSE_ACCEPT && smppair->entry) {
        GtkEntry* entry = smppair->entry;
        char *secret;
        size_t secret_len;

        GtkEntry* question_entry = smppair->question_entry;
    
        const char *user_question = NULL;


        if (context == NULL || context->msgstate != OTRL_MSGSTATE_ENCRYPTED) {
            return;
        }
    
        secret = g_strdup(gtk_entry_get_text(entry));
        secret_len = strlen(secret);

        if (smppair->responder) {
            otrg_plugin_continue_smp(context, (const unsigned char *)secret,
                secret_len);
            
        } else {
            
            if (smppair->smp_type == 0) {
                if (!question_entry) {
                    return;
                }
              
                user_question = gtk_entry_get_text(question_entry);
        
                if (user_question == NULL || strlen(user_question) == 0) {
                    return;
                }
            }

            /* pass user question here */
            otrg_plugin_start_smp(context, user_question,
	           (const unsigned char *)secret, secret_len);

        }
    
        g_free(secret);

        /* launch progress bar window */
        create_smp_progress_dialog(GTK_WINDOW(dialog), context);
    } else if (response == GTK_RESPONSE_HELP) {
	char *helpurl = g_strdup_printf("%s%s&context=%s",
		AUTHENTICATE_HELPURL, _("?lang=en"),
		auth_opt_data->smppair->smp_type == 0 ?
		    ( /* Question and Answer */
		      auth_opt_data->smppair->responder ?
		      "answer" : "question" ) :
		auth_opt_data->smppair->smp_type == 1 ?
		    ( /* Shared secret */
		      auth_opt_data->smppair->responder ?
		      "secretresp" : "secret" ) :
		    /* Fingerprint */
		    "fingerprint"
		);
	purple_notify_uri(otrg_plugin_handle, helpurl);
	g_free(helpurl);

	/* Don't destroy the window */
	return;
    } else {
        otrg_plugin_abort_smp(context);
    }
    
    /* In all cases except HELP, destroy the current window */
    gtk_widget_destroy(GTK_WIDGET(dialog));
    
    /* Clean up references to this window */
    conv = otrg_plugin_context_to_conv(smppair->context, 0);
    smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    
    if (smp_data) {
        smp_data->smp_secret_dialog = NULL;
        smp_data->smp_secret_smppair = NULL;
    }

    /* Free memory */
    free(auth_opt_data);
    free(smppair);
}

static void close_smp_window(PurpleConversation *conv)
{
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    if (smp_data && smp_data->smp_secret_dialog) {
	gtk_dialog_response(GTK_DIALOG(smp_data->smp_secret_dialog),
		GTK_RESPONSE_REJECT);
    }
}

static GtkWidget *create_dialog(GtkWindow *parent,
	PurpleNotifyMsgType type, const char *title,
	const char *primary, const char *secondary, int sensitive,
	GtkWidget **labelp, void (*add_custom)(GtkWidget *vbox, void *data),
	void *add_custom_data)
{
    GtkWidget *dialog;
    GtkWidget *hbox;
    GtkWidget *vbox;
    GtkWidget *label;
    GtkWidget *img = NULL;
    char *label_text;
    const char *icon_name = NULL;

    switch (type) {
	case PURPLE_NOTIFY_MSG_ERROR:
	    icon_name = PIDGIN_STOCK_DIALOG_ERROR;
	    break;

	case PURPLE_NOTIFY_MSG_WARNING:
	    icon_name = PIDGIN_STOCK_DIALOG_WARNING;
	    break;

	case PURPLE_NOTIFY_MSG_INFO:
	    icon_name = PIDGIN_STOCK_DIALOG_INFO;
	    break;

	default:
	    icon_name = NULL;
	    break;
    }

    if (icon_name != NULL) {
	img = gtk_image_new_from_stock(icon_name,
		gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
	gtk_misc_set_alignment(GTK_MISC(img), 0, 0);
    }

    dialog = gtk_dialog_new_with_buttons(
	    title ? title : PIDGIN_ALERT_TITLE, parent, 0,
	    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);

    gtk_window_set_focus_on_map(GTK_WINDOW(dialog), FALSE);
    gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

    g_signal_connect(G_OBJECT(dialog), "response",
			 G_CALLBACK(message_response_cb), dialog);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT,
	    sensitive);

    gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
    gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
    gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), 6);

    hbox = gtk_hbox_new(FALSE, 12);
    vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);

    if (img != NULL) {
	gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);
    }

    label_text = g_strdup_printf(
		       "<span weight=\"bold\" size=\"larger\">%s</span>%s%s",
		       (primary ? primary : ""),
		       (primary ? "\n\n" : ""),
		       (secondary ? secondary : ""));

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), 1);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    if (add_custom) {
	add_custom(vbox, add_custom_data);
    }
    gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

    gtk_widget_show_all(dialog);

    if (labelp) *labelp = label;
    return dialog;
}

static void add_to_vbox_init_one_way_auth(GtkWidget *vbox,
	ConnContext *context, AuthSignalData *auth_opt_data, char *question) {
    GtkWidget *question_entry;
    GtkWidget *entry;
    GtkWidget *label;
    GtkWidget *label2;
    char *label_text;   
    
    SmpResponsePair* smppair = auth_opt_data->smppair;
    
    if (smppair->responder) {
        label_text = g_strdup_printf("<small><i>\n%s\n</i></small>",
	    _("Your buddy is attempting to determine if he or she is really "
		"talking to you, or if it's someone pretending to be you.  "
		"Your buddy has asked a question, indicated below.  "
		"To authenticate to your buddy, enter the answer and "
		"click OK."));
    } else {
        label_text = g_strdup_printf("<small><i>\n%s\n</i></small>",
	    _("To authenticate using a question, pick a question whose "
	    "answer is known only to you and your buddy.  Enter this "
	    "question and this answer, then wait for your buddy to "
	    "enter the answer too.  If the answers "
	    "don't match, then you may be talking to an imposter."));
    }

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
       
       
    if (smppair->responder) {
        label_text = g_strdup_printf(_("This is the question asked by "
		    "your buddy:"));
    } else {
        label_text = g_strdup_printf(_("Enter question here:"));
    }
    
    label = gtk_label_new(label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    

    
    if (smppair->responder && question) {
        label_text = g_markup_printf_escaped("<span background=\"white\" foreground=\"black\" weight=\"bold\">%s</span>", question);
        label = gtk_label_new(NULL);
        gtk_label_set_markup (GTK_LABEL(label), label_text);
        gtk_label_set_selectable(GTK_LABEL(label), FALSE);
        g_free(label_text);
        gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
        gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
        gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
        smppair->question_entry = NULL;
    } else {
        /* Create the text view where the user enters their question */
        question_entry = gtk_entry_new ();
        smppair->question_entry = GTK_ENTRY(question_entry);
        gtk_box_pack_start(GTK_BOX(vbox), question_entry, FALSE, FALSE, 0);
    }
    
    if (context->active_fingerprint->trust &&
        context->active_fingerprint->trust[0] && !(smppair->responder)) {
        label2 = gtk_label_new(_("This buddy is already authenticated."));
    } else {
        label2 = NULL;
    }

    
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
        FALSE, 0);

    label_text = g_strdup_printf(_("Enter secret answer here "
		"(case sensitive):"));

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    /* Create the text view where the user enters their secret */
    entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(entry), "");

    auth_opt_data->one_way_entry = GTK_ENTRY(entry);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), smppair->responder);

    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
        FALSE, 0);
        
    if (label2) {
        gtk_box_pack_start(GTK_BOX(vbox), label2, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
            FALSE, 0);
    }
}

static void add_to_vbox_init_two_way_auth(GtkWidget *vbox,
	ConnContext *context, AuthSignalData *auth_opt_data) {
    GtkWidget *entry;
    GtkWidget *label;
    GtkWidget *label2;
    char *label_text;   
    
    label_text = g_strdup_printf("<small><i>\n%s\n</i></small>",
        _("To authenticate, pick a secret known "
            "only to you and your buddy.  Enter this secret, then "
            "wait for your buddy to enter it too.  If the secrets "
            "don't match, then you may be talking to an imposter."));

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
       
    label_text = g_strdup_printf(_("Enter secret here:"));
    label = gtk_label_new(label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
        
       
    /* Create the text view where the user enters their secret */
    entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(entry), "");
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    auth_opt_data->two_way_entry = GTK_ENTRY(entry);

    if (context->active_fingerprint->trust &&
        context->active_fingerprint->trust[0]) {
        label2 = gtk_label_new(_("This buddy is already authenticated."));
    } else {
        label2 = NULL;
    }

    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
        FALSE, 0);
        
    if (label2) {
        gtk_box_pack_start(GTK_BOX(vbox), label2, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
            FALSE, 0);
    }
}

static void add_to_vbox_verify_fingerprint(GtkWidget *vbox, ConnContext *context, SmpResponsePair* smppair) {
    char our_hash[45], their_hash[45];
    GtkWidget *label;
    char *label_text;
    struct vrfy_fingerprint_data *vfd;
    PurplePlugin *p;
    char *proto_name;
    Fingerprint *fprint = context->active_fingerprint;

    if (fprint == NULL) return;
    if (fprint->fingerprint == NULL) return;
    context = fprint->context;
    if (context == NULL) return;

    label_text = g_strdup_printf("<small><i>\n%s %s\n</i></small>",
	    _("To verify the fingerprint, contact your buddy via some "
	    "<i>other</i> authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your fingerprint "
	    "to the other."),
	    _("If everything matches up, you should indicate in the above "
	    "dialog that you <b>have</b> verified the fingerprint."));
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    vfd = vrfy_fingerprint_data_new(fprint);

    strcpy(our_hash, _("[none]"));
    otrl_privkey_fingerprint(otrg_plugin_userstate, our_hash,
        context->accountname, context->protocol);

    otrl_privkey_hash_to_human(their_hash, fprint->fingerprint);

    p = purple_find_prpl(context->protocol);
    proto_name = (p && p->info->name) ? p->info->name : _("Unknown");
    label_text = g_strdup_printf(_("Fingerprint for you, %s (%s):\n%s\n\n"
        "Purported fingerprint for %s:\n%s\n"), context->accountname,
        proto_name, our_hash, context->username, their_hash);
        
    label = gtk_label_new(NULL);
    
    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
        
    add_vrfy_fingerprint(vbox, vfd);
    g_signal_connect(G_OBJECT(vbox), "destroy",
	    G_CALLBACK(vrfy_fingerprint_destroyed), vfd);
}

static void redraw_auth_vbox(GtkComboBox *combo, void *data) {
    AuthSignalData *auth_data = (AuthSignalData*) data;

    GtkWidget *notebook = auth_data ? auth_data->notebook : NULL;

    int selected;
    
    if (auth_data == NULL) return;

    selected = gtk_combo_box_get_active(combo);
    
    if (selected == 0) {
        gtk_notebook_set_current_page (GTK_NOTEBOOK(notebook), 0);
        auth_data->smppair->entry = auth_data->one_way_entry;
        auth_data->smppair->smp_type = 0;
    } else if (selected == 1) {
        gtk_notebook_set_current_page (GTK_NOTEBOOK(notebook), 1);
        auth_data->smppair->entry = auth_data->two_way_entry;
        auth_data->smppair->smp_type = 1;
    } else if (selected == 2) {
        auth_data->smppair->entry = NULL;
        gtk_notebook_set_current_page (GTK_NOTEBOOK(notebook), 2);
        auth_data->smppair->smp_type = -1;
    }
    
}

static void add_other_authentication_options(GtkWidget *vbox,
	GtkWidget *notebook, ConnContext *context, AuthSignalData *data) {
    GtkWidget *label;
    GtkWidget *combo;
    char *labeltext;

    labeltext = g_strdup_printf("\n%s",
	_("How would you like to authenticate your buddy?"));
    label = gtk_label_new(labeltext);
    g_free(labeltext);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    combo = gtk_combo_box_new_text();

    gtk_combo_box_append_text(GTK_COMBO_BOX(combo),
	    _("Question and answer"));

    gtk_combo_box_append_text(GTK_COMBO_BOX(combo),
	    _("Shared secret"));

    gtk_combo_box_append_text(GTK_COMBO_BOX(combo),
	    _("Manual fingerprint verification"));

    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    gtk_box_pack_start(GTK_BOX(vbox), combo, FALSE, FALSE, 0);

    data->notebook = notebook;
   
    g_signal_connect (combo, "changed",
                  G_CALLBACK (redraw_auth_vbox), data);
}


static GtkWidget *create_smp_dialog(const char *title, const char *primary,
	ConnContext *context, gboolean responder, char *question)
{
    GtkWidget *dialog;

    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 1);
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");

    close_progress_window(smp_data);
    
    if (!(smp_data->smp_secret_dialog)) {
        GtkWidget *hbox;
        GtkWidget *vbox;
        GtkWidget *auth_vbox;
        GtkWidget *label;
        GtkWidget *img = NULL;
        char *label_text;
        const char *icon_name = NULL;
        SmpResponsePair* smppair;
        GtkWidget *notebook;
        AuthSignalData *auth_opt_data;     
    
        icon_name = PIDGIN_STOCK_DIALOG_INFO;
        img = gtk_image_new_from_stock(icon_name,
		gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
        gtk_misc_set_alignment(GTK_MISC(img), 0, 0);
    
        dialog = gtk_dialog_new_with_buttons(title ? title :
		PIDGIN_ALERT_TITLE, NULL, 0,
                         GTK_STOCK_HELP, GTK_RESPONSE_HELP,
                         GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
                         _("_Authenticate"), GTK_RESPONSE_ACCEPT, NULL);
        gtk_dialog_set_default_response(GTK_DIALOG(dialog),
		GTK_RESPONSE_ACCEPT);
    
        auth_vbox = gtk_vbox_new(FALSE, 0);
        hbox = gtk_hbox_new(FALSE, 15);
        vbox = gtk_vbox_new(FALSE, 0);
        
        smppair = malloc(sizeof(SmpResponsePair));
        smppair->responder = responder;
        smppair->context = context;
        
        
        notebook = gtk_notebook_new();
        auth_opt_data = malloc(sizeof(AuthSignalData)); 
        auth_opt_data->smppair = smppair;
        
        gtk_window_set_focus_on_map(GTK_WINDOW(dialog), !responder);
        gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");
    
        gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
        gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
        gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
        gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
        gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), 6);
    
        gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);
    
        gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);
    
        label_text = g_strdup_printf(
               "<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s",
               (primary ? primary : ""),
		_("Authenticating a buddy helps ensure that the person "
		    "you are talking to is who he or she claims to be."));
    
        label = gtk_label_new(NULL);
    
        gtk_label_set_markup(GTK_LABEL(label), label_text);
        gtk_label_set_selectable(GTK_LABEL(label), FALSE);
        g_free(label_text);
        gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
        gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
        gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
        if (!responder) {
            add_other_authentication_options(vbox, notebook, context, auth_opt_data);
        }
        
        g_signal_connect(G_OBJECT(dialog), "response",
                 G_CALLBACK(smp_secret_response_cb),
                 auth_opt_data);
    
        if (!responder || (responder && question != NULL)) {
            GtkWidget *one_way_vbox = gtk_vbox_new(FALSE, 0);
            add_to_vbox_init_one_way_auth(one_way_vbox, context,
		    auth_opt_data, question);
            gtk_notebook_append_page(GTK_NOTEBOOK(notebook), one_way_vbox,
                gtk_label_new("0"));
            smppair->entry = auth_opt_data->one_way_entry;
            smppair->smp_type = 0;
        }
        
        if (!responder || (responder && question == NULL)) {
            GtkWidget *two_way_vbox = gtk_vbox_new(FALSE, 0);
            add_to_vbox_init_two_way_auth(two_way_vbox, context, auth_opt_data);
            gtk_notebook_append_page(GTK_NOTEBOOK(notebook), two_way_vbox,
                gtk_label_new("1"));
                    
            if (responder && question == NULL) {
                smppair->entry = auth_opt_data->two_way_entry;
                smppair->smp_type = 1;
            }
        }
        
        if (!responder) {
            GtkWidget *fingerprint_vbox = gtk_vbox_new(FALSE, 0);
            add_to_vbox_verify_fingerprint(fingerprint_vbox, context, smppair);
            gtk_notebook_append_page(GTK_NOTEBOOK(notebook), fingerprint_vbox,
                gtk_label_new("2"));
        }
        
        gtk_notebook_set_show_tabs (GTK_NOTEBOOK(notebook), FALSE);
        
        gtk_notebook_set_show_border (GTK_NOTEBOOK(notebook), FALSE);
        gtk_box_pack_start(GTK_BOX(auth_vbox), notebook, FALSE, FALSE, 0);
        gtk_widget_show(notebook);
    
    
        gtk_box_pack_start(GTK_BOX(vbox), auth_vbox, FALSE, FALSE, 0);
        
        gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);
    
        gtk_widget_show_all(dialog);
        
        gtk_notebook_set_current_page (GTK_NOTEBOOK(notebook), 0);

	if (!responder) {
	    gtk_window_set_focus(GTK_WINDOW(dialog),
		    GTK_WIDGET(smppair->question_entry));
	} else {
	    gtk_window_set_focus(GTK_WINDOW(dialog),
		    GTK_WIDGET(smppair->entry));
	}
        
        smp_data->smp_secret_dialog = dialog;
        smp_data->smp_secret_smppair = smppair;
    
    } else {
        /* Set the responder field to TRUE if we were passed that value,
         * even if the window was already up. */
        if (responder) {
            smp_data->smp_secret_smppair->responder = responder;
        }
    }

    return smp_data->smp_secret_dialog;
}

static GtkWidget *create_smp_progress_dialog(GtkWindow *parent,
	ConnContext *context)
{
    GtkWidget *dialog;
    GtkWidget *hbox;
    GtkWidget *vbox;
    GtkWidget *label;
    GtkWidget *proglabel;
    GtkWidget *bar;
    GtkWidget *img = NULL;
    char *label_text, *label_pat;
    const char *icon_name = NULL;
    PurpleConversation *conv;
    SMPData *smp_data;

    icon_name = PIDGIN_STOCK_DIALOG_INFO;
    img = gtk_image_new_from_stock(icon_name,
	    gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
    gtk_misc_set_alignment(GTK_MISC(img), 0, 0);

    dialog = gtk_dialog_new_with_buttons(
	    context->smstate->received_question ?
            /* Translators: you are asked to authenticate yourself */
	    _("Authenticating to Buddy") :
            /* Translators: you asked your buddy to authenticate him/herself */
	    _("Authenticating Buddy"),
	    parent, 0, GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
	    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog),
	    GTK_RESPONSE_ACCEPT);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog),
	    GTK_RESPONSE_REJECT, 1);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog),
	    GTK_RESPONSE_ACCEPT, 0);

    gtk_window_set_focus_on_map(GTK_WINDOW(dialog), FALSE);
    gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

    gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
    gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
    gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), 6);

    hbox = gtk_hbox_new(FALSE, 12);
    vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);

    gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);

    label_pat = g_strdup_printf("<span weight=\"bold\" size=\"larger\">"
	    "%s</span>\n", context->smstate->received_question ?
		   _("Authenticating to %s") :
		   _("Authenticating %s"));
    label_text = g_strdup_printf(label_pat, context->username);
    g_free(label_pat);

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), 1);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    proglabel = gtk_label_new(NULL);
    gtk_label_set_selectable(GTK_LABEL(proglabel), 1);
    gtk_label_set_line_wrap(GTK_LABEL(proglabel), TRUE);
    gtk_misc_set_alignment(GTK_MISC(proglabel), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), proglabel, FALSE, FALSE, 0);
   
    /* Create the progress bar */
    bar = gtk_progress_bar_new();
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(bar), 0.1);
    gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

    conv = otrg_plugin_context_to_conv(context, 0);
    smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    if (smp_data) {
	smp_data->smp_progress_dialog = dialog;
	smp_data->smp_progress_bar = bar;
	smp_data->smp_progress_label = proglabel;
    }
    gtk_label_set_text(GTK_LABEL(proglabel), _("Waiting for buddy..."));

    g_signal_connect(G_OBJECT(dialog), "response",
		     G_CALLBACK(smp_progress_response_cb),
		     context);

    gtk_widget_show_all(dialog);

    return dialog;
}
#endif

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

static void otrg_purple_dialog_clicked_connect(GtkWidget *widget, gpointer data);

static void destroy_menuitem(GtkWidget *widget, gpointer data)
{
    gtk_widget_destroy(widget);
}

static void dialog_update_label_conv(PurpleConversation *conv, TrustLevel level)
{
    purple_conversation_set_data(conv, "otr-level", GINT_TO_POINTER(level));
    purple_conversation_update(conv, PURPLE_CONV_UPDATE_FEATURES);
}

static void dialog_update_label(PurpleConversation *conv, ConnContext *context)
{
    TrustLevel level = otrg_plugin_context_to_trust(context);
    dialog_update_label_conv(conv, level);
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

static void vrfy_fingerprint_destroyed(GtkWidget *w,
	struct vrfy_fingerprint_data *vfd)
{
    vrfy_fingerprint_data_free(vfd);
}

static void vrfy_fingerprint_changed(GtkComboBox *combo, void *data)
{
    struct vrfy_fingerprint_data *vfd = data;
    ConnContext *context = otrl_context_find(otrg_plugin_userstate,
	    vfd->username, vfd->accountname, vfd->protocol, 0, NULL,
	    NULL, NULL);
    Fingerprint *fprint;
    int oldtrust, trust;

    if (context == NULL) return;

    fprint = otrl_context_find_fingerprint(context, vfd->fingerprint,
	    0, NULL);

    if (fprint == NULL) return;

    oldtrust = (fprint->trust && fprint->trust[0]);
    trust = gtk_combo_box_get_active(combo) == 1 ? 1 : 0;

    /* See if anything's changed */
    if (trust != oldtrust) {
	otrl_context_set_trust(fprint, trust ? "verified" : "");
	/* Write the new info to disk, redraw the ui, and redraw the
	 * OTR buttons. */
	otrg_plugin_write_fingerprints();
	otrg_ui_update_keylist();
	otrg_dialog_resensitize_all();
    
    }
}

/* Add the verify widget and the help text for the verify fingerprint box. */
static void add_vrfy_fingerprint(GtkWidget *vbox, void *data)
{
    GtkWidget *hbox;
    GtkWidget *combo, *label;
    struct vrfy_fingerprint_data *vfd = data;
    char *labelt;
    int verified = 0;

    if (vfd->fprint->trust && vfd->fprint->trust[0]) {
	verified = 1;
    }

    hbox = gtk_hbox_new(FALSE, 0);
    combo = gtk_combo_box_new_text();
    /* Translators: the following four messages should give alternative sentences.
       The user selects the first or second message in a combo box;
      the third message, a new line, a fingerprint, a new line, and 
      the fourth message will follow it. */
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), _("I have not"));
    /* 2nd message */
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), _("I have"));
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), verified);
    /* 3rd message */
    label = gtk_label_new(_(" verified that this is in fact the correct"));
    gtk_box_pack_start(GTK_BOX(hbox), combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    g_signal_connect(G_OBJECT(combo), "changed",
	    G_CALLBACK(vrfy_fingerprint_changed), vfd);

    hbox = gtk_hbox_new(FALSE, 0);
    /* 4th message */
    labelt = g_strdup_printf(_("fingerprint for %s."),
	    vfd->username);
    label = gtk_label_new(labelt);
    g_free(labelt);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
    
    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);
}

static void verify_fingerprint(GtkWindow *parent, Fingerprint *fprint)
{
#if 0
    GtkWidget *dialog;
    char our_hash[45], their_hash[45];
    char *primary;
    char *secondary;
    struct vrfy_fingerprint_data *vfd;
    ConnContext *context;
    PurplePlugin *p;
    char *proto_name;

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
    secondary = g_strdup_printf(_("<small><i>%s %s\n\n</i></small>"
		"Fingerprint for you, %s (%s):\n%s\n\n"
		"Purported fingerprint for %s:\n%s\n"),
	    _("To verify the fingerprint, contact your buddy via some "
	    "<i>other</i> authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your fingerprint "
	    "to the other."),
	    _("If everything matches up, you should indicate in the above "
	    "dialog that you <b>have</b> verified the fingerprint."),
	    context->accountname, proto_name, our_hash,
	    context->username, their_hash);

    dialog = create_dialog(parent, PURPLE_NOTIFY_MSG_INFO,
	    _("Verify fingerprint"), primary, secondary, 1, NULL,
	    add_vrfy_fingerprint, vfd);
    g_signal_connect(G_OBJECT(dialog), "destroy",
	    G_CALLBACK(vrfy_fingerprint_destroyed), vfd);

    g_free(primary);
    g_free(secondary);
#endif
}

static void otrg_purple_dialog_verify_fingerprint(Fingerprint *fprint)
{
    verify_fingerprint(NULL, fprint);
}

/* Create the SMP dialog.  responder is true if this is called in
 * response to someone else's run of SMP. */
static void otrg_purple_dialog_socialist_millionaires(ConnContext *context,
	char *question, gboolean responder)
{
#if 0
    GtkWidget *dialog;
    char *primary;
    PurplePlugin *p;
    char *proto_name;

    if (context == NULL) return;

    if (responder && question) {
        primary = g_strdup_printf(_("Authentication from %s"),
            context->username);
    } else {
        primary = g_strdup_printf(_("Authenticate %s"),
            context->username);
    }
    
    /* fprintf(stderr, "Question = ``%s''\n", question); */

    p = purple_find_prpl(context->protocol);
    proto_name = (p && p->info->name) ? p->info->name : _("Unknown");
    

    dialog = create_smp_dialog(_("Authenticate Buddy"),
	    primary, context, responder, question);

    g_free(primary);
#endif
}

/* Call this to update the status of an ongoing socialist millionaires
 * protocol.  Progress_level is a percentage, from 0.0 (aborted) to
 * 1.0 (complete).  Any other value represents an intermediate state. */
static void otrg_purple_dialog_update_smp(ConnContext *context,
	double progress_level)
{
#if 0
    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 0);
    GtkProgressBar *bar;
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");

    if (!smp_data) return;

    bar = GTK_PROGRESS_BAR(smp_data->smp_progress_bar);
    gtk_progress_bar_set_fraction(bar, progress_level);

    /* If the counter is reset to absolute zero, the protocol has aborted */
    if (progress_level == 0.0) {
        GtkDialog *dialog = GTK_DIALOG(smp_data->smp_progress_dialog);

	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_ACCEPT, 1);
	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_REJECT, 0);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog),
		GTK_RESPONSE_ACCEPT);

	gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
		_("An error occurred during authentication."));
	return;
    } else if (progress_level == 1.0) {
	/* If the counter reaches 1.0, the protocol is complete */
        GtkDialog *dialog = GTK_DIALOG(smp_data->smp_progress_dialog);

	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_ACCEPT, 1);
	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_REJECT, 0);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog),
		GTK_RESPONSE_ACCEPT);

        if (context->smstate->sm_prog_state == OTRL_SMP_PROG_SUCCEEDED) {
	    if (context->active_fingerprint->trust &&
		    context->active_fingerprint->trust[0]) {
		gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
			_("Authentication successful."));
	    } else {
		gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
			_("Your buddy has successfully authenticated you.  "
			    "You may want to authenticate your buddy as "
			    "well by asking your own question."));
	    }
        } else {
	    gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
		    _("Authentication failed."));
	}
    } else {
	/* Clear the progress label */
	gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label), "");
    }
#endif
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

    dialog_update_label(conv, context);
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

    dialog_update_label(conv, context);
/*    close_smp_window(conv); */
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
/*    close_smp_window(conv); */
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

    dialog_update_label(conv, context);
}

/* Called when SMP verification option selected from menu */
static void socialist_millionaires(GtkWidget *widget, gpointer data)
{
    PurpleConversation *conv = data;
    ConnContext *context = otrg_plugin_conv_to_context(conv);

    if (context == NULL || context->msgstate != OTRL_MSGSTATE_ENCRYPTED)
	return;

    otrg_purple_dialog_socialist_millionaires(context, NULL, FALSE);
}

static void menu_whatsthis(GtkWidget *widget, gpointer data)
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

/*    otrg_purple_dialog_free_smp_data(conv); */
}

/* Set up the per-conversation information display */
static void otrg_purple_dialog_new_conv(PurpleConversation *conv)
{
	/* Nothing to do */
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
