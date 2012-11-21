/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010  ProFUSION embedded systems
 *  Copyright (C) 2011  BMW Car IT GmbH. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <glib.h>
#include <gatchat.h>
#include <gattty.h>
#include <gdbus.h>
#include <ofono.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>
#include <ofono/netreg.h>
#include <ofono/voicecall.h>
#include <ofono/call-volume.h>
#include <ofono/handsfree.h>

#include <drivers/hfpmodem/slc.h>

#include "bluetooth.h"

#define HFP_EXT_PROFILE_PATH   "/bluetooth/profile/hfp_hf"

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

static DBusConnection *connection;
static GHashTable *modem_hash = NULL;
static GHashTable *hfp_hash = NULL;

struct hfp_data {
	struct hfp_slc_info info;
	gchar *device_address;
	gchar *adapter_address;
	gchar *device_alias;
	gchar *device_path;
	DBusMessage *slc_msg;
};

static void hfp_data_free(gpointer user_data)
{
	struct hfp_data *hfp_data = user_data;

	g_free(hfp_data->device_address);
	g_free(hfp_data->adapter_address);
	g_free(hfp_data->device_alias);
	g_free(hfp_data->device_path);
	g_free(hfp_data);
}

static void hfp_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static void slc_established(gpointer userdata)
{
	struct ofono_modem *modem = userdata;
	struct hfp_data *data = ofono_modem_get_data(modem);
	DBusMessage *msg;

	ofono_modem_set_powered(modem, TRUE);

	msg = dbus_message_new_method_return(data->slc_msg);
	g_dbus_send_message(connection, msg);
	dbus_message_unref(data->slc_msg);
	data->slc_msg = NULL;

	ofono_info("Service level connection established");
}

static void slc_failed(gpointer userdata)
{
	struct ofono_modem *modem = userdata;
	struct hfp_data *data = ofono_modem_get_data(modem);
	DBusMessage *msg;

	msg = g_dbus_create_error(data->slc_msg, BLUEZ_ERROR_INTERFACE
						".Failed",
						"HFP Handshake failed");

	g_dbus_send_message(connection, msg);
	dbus_message_unref(data->slc_msg);
	data->slc_msg = NULL;

	ofono_error("Service level connection failed");
	ofono_modem_set_powered(modem, FALSE);

	g_at_chat_unref(data->info.chat);
	data->info.chat = NULL;
}

static void hfp_disconnected_cb(gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct hfp_data *data = ofono_modem_get_data(modem);

	ofono_modem_set_powered(modem, FALSE);

	g_at_chat_unref(data->info.chat);
	data->info.chat = NULL;

	g_hash_table_remove(modem_hash, data->device_path);

	ofono_modem_remove(modem);
}

/* either oFono or Phone could request SLC connection */
static int service_level_connection(struct ofono_modem *modem, int fd)
{
	struct hfp_data *data = ofono_modem_get_data(modem);
	GIOChannel *io;
	GAtSyntax *syntax;
	GAtChat *chat;

	io = g_io_channel_unix_new(fd);
	if (io == NULL) {
		ofono_error("Service level connection failed: %s (%d)",
			strerror(errno), errno);
		return -EIO;
	}

	syntax = g_at_syntax_new_gsm_permissive();
	chat = g_at_chat_new(io, syntax);
	g_at_syntax_unref(syntax);
	g_io_channel_unref(io);

	if (chat == NULL)
		return -ENOMEM;

	g_at_chat_set_disconnect_function(chat, hfp_disconnected_cb, modem);

	if (getenv("OFONO_AT_DEBUG"))
		g_at_chat_set_debug(chat, hfp_debug, "");

	data->info.chat = chat;
	hfp_slc_establish(&data->info, slc_established, slc_failed, modem);

	return -EINPROGRESS;
}

static int modem_register(const char *device, struct hfp_data *hfp_data, int fd)
{
	struct ofono_modem *modem;
	char buf[256];
	guint16 version = 0x0105;

	/* We already have this device in our hash, ignore */
	if (g_hash_table_lookup(modem_hash, device) != NULL)
		return -EALREADY;

	strcpy(buf, "hfp/");
	bluetooth_create_path(hfp_data->device_address,
			hfp_data->adapter_address, buf + 4, sizeof(buf) - 4);

	modem = ofono_modem_create(buf, "hfp");
	if (modem == NULL)
		return -ENOMEM;

	ofono_modem_set_data(modem, hfp_data);
	ofono_modem_set_name(modem, hfp_data->device_alias);
	ofono_modem_register(modem);

	g_hash_table_insert(modem_hash, g_strdup(device), modem);

	hfp_slc_info_init(&hfp_data->info, version);

	return service_level_connection(modem, fd);
}

static int hfp_hf_probe(const char *device, const char *dev_addr,
				const char *adapter_addr, const char *alias)
{
	struct hfp_data *hfp_data;

	if (g_hash_table_lookup(hfp_hash, device) != NULL)
		return -EALREADY;

	ofono_info("Using device: %s, devaddr: %s, adapter: %s",
					device, dev_addr, adapter_addr);

	hfp_data = g_try_new0(struct hfp_data, 1);
	if (hfp_data == NULL)
		goto free;

	hfp_data->adapter_address = g_strdup(adapter_addr);
	if (hfp_data->adapter_address == NULL)
		goto free;

	hfp_data->device_address = g_strdup(dev_addr);
	if (hfp_data->device_address == NULL)
		goto free;

	hfp_data->device_path = g_strdup(device);
	if (hfp_data->device_path == NULL)
		goto free;

	hfp_data->device_alias = g_strdup(alias);
	if (hfp_data->device_alias == NULL)
		goto free;

	g_hash_table_insert(hfp_hash, g_strdup(device), hfp_data);

	return 0;

free:
	hfp_data_free(hfp_data);

	return -ENOMEM;
}

static gboolean hfp_remove_modem(gpointer key, gpointer value,
					gpointer user_data)
{
	struct ofono_modem *modem = value;
	const char *device = key;
	const char *prefix = user_data;

	if (prefix && g_str_has_prefix(device, prefix) == FALSE)
		return FALSE;

	ofono_modem_remove(modem);

	return TRUE;
}

static void hfp_hf_remove(const char *prefix)
{
	DBG("%s", prefix);

	if (modem_hash == NULL)
		return;

	g_hash_table_foreach_remove(modem_hash, hfp_remove_modem,
							(gpointer) prefix);
}

static void hfp_hf_set_alias(const char *device, const char *alias)
{
	struct ofono_modem *modem;

	if (device == NULL || alias == NULL)
		return;

	modem =	g_hash_table_lookup(modem_hash, device);
	if (modem == NULL)
		return;

	ofono_modem_set_name(modem, alias);
}

static DBusMessage *profile_new_connection(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct hfp_data *hfp_data;
	const char *device;
	DBusMessageIter entry;
	int fd, err;

	DBG("Profile handler NewConnection");

	if (dbus_message_iter_init(msg, &entry) == FALSE)
		goto error;

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_OBJECT_PATH)
		goto error;

	dbus_message_iter_get_basic(&entry, &device);
	hfp_data = g_hash_table_lookup(hfp_hash, device);
	if (hfp_data == NULL) {
		DBG("%s: doesn't support HFP", device);
		goto error;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_UNIX_FD)
		goto error;

	dbus_message_iter_get_basic(&entry, &fd);
	if (fd < 0)
		goto error;

	DBG("hfp_data: %p SLC FD: %d", hfp_data, fd);

	err = modem_register(device, hfp_data, fd);
	if (err < 0 && err != -EINPROGRESS)
		return __ofono_error_failed(msg);

	hfp_data->slc_msg = dbus_message_ref(msg);

	return NULL;

error:
	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE ".Rejected",
					"Invalid arguments in method call");
}

static DBusMessage *profile_release(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("Profile handler Release");

	g_dbus_unregister_interface(connection, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);

	g_hash_table_foreach_remove(modem_hash, hfp_remove_modem, NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *profile_cancel(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("Profile handler Cancel");
	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static DBusMessage *profile_disconnection(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("Profile handler RequestDisconnection");
	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static const GDBusMethodTable profile_methods[] = {
	{ GDBUS_ASYNC_METHOD("NewConnection",
				GDBUS_ARGS({ "device", "o"}, { "fd", "h"},
						{ "fd_properties", "a{sv}" }),
				NULL, profile_new_connection) },
	{ GDBUS_METHOD("Release", NULL, NULL, profile_release) },
	{ GDBUS_METHOD("Cancel", NULL, NULL, profile_cancel) },
	{ GDBUS_METHOD("RequestDisconnection",
				GDBUS_ARGS({"device", "o"}), NULL,
				profile_disconnection) },
	{ }
};

static int hfp_probe(struct ofono_modem *modem)
{
	DBG("modem: %p", modem);

	return 0;
}

static void hfp_remove(struct ofono_modem *modem)
{
	DBG("modem: %p", modem);
}

/* power up hardware */
static int hfp_enable(struct ofono_modem *modem)
{
	DBG("%p", modem);

	if (ofono_modem_get_powered(modem))
		return 0;

	return -ENOTCONN;
}

static int hfp_disable(struct ofono_modem *modem)
{
	struct hfp_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	g_at_chat_unref(data->info.chat);
	data->info.chat = NULL;

	ofono_modem_set_powered(modem, FALSE);

	return 0;
}

static void hfp_pre_sim(struct ofono_modem *modem)
{
	struct hfp_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_devinfo_create(modem, 0, "hfpmodem", data->device_address);
	ofono_voicecall_create(modem, 0, "hfpmodem", &data->info);
	ofono_netreg_create(modem, 0, "hfpmodem", &data->info);
	ofono_call_volume_create(modem, 0, "hfpmodem", &data->info);
	ofono_handsfree_create(modem, 0, "hfpmodem", &data->info);
}

static void hfp_post_sim(struct ofono_modem *modem)
{
	DBG("%p", modem);
}

static struct ofono_modem_driver hfp_driver = {
	.name		= "hfp",
	.modem_type	= OFONO_MODEM_TYPE_HFP,
	.probe		= hfp_probe,
	.remove		= hfp_remove,
	.enable		= hfp_enable,
	.disable	= hfp_disable,
	.pre_sim	= hfp_pre_sim,
	.post_sim	= hfp_post_sim,
};

static struct bluetooth_profile hfp_hf = {
	.name		= "hfp_hf",
	.probe		= hfp_hf_probe,
	.remove		= hfp_hf_remove,
	.set_alias	= hfp_hf_set_alias,
};

static int hfp_init(void)
{
	int err;

	if (DBUS_TYPE_UNIX_FD < 0)
		return -EBADF;

	connection = ofono_dbus_get_connection();

	/* Registers External Profile handler */
	if (!g_dbus_register_interface(connection, HFP_EXT_PROFILE_PATH,
					BLUEZ_PROFILE_INTERFACE,
					profile_methods, NULL,
					NULL, NULL, NULL)) {
		ofono_error("Register Profile interface failed: %s",
							HFP_EXT_PROFILE_PATH);
		return -EIO;
	}

	err = ofono_modem_driver_register(&hfp_driver);
	if (err < 0)
		return err;

	err = bluetooth_register_uuid(HFP_AG_UUID, &hfp_hf);
	if (err < 0) {
		g_dbus_unregister_interface(connection, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);
		ofono_modem_driver_unregister(&hfp_driver);
		return err;
	}

	err = bluetooth_register_profile(HFP_HS_UUID, "hfp_hf",
						HFP_EXT_PROFILE_PATH);
	if (err < 0) {
		g_dbus_unregister_interface(connection, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);
		bluetooth_unregister_uuid(HFP_AG_UUID);
		ofono_modem_driver_unregister(&hfp_driver);
		return err;
	}

	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, NULL);

	hfp_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
								hfp_data_free);

	return 0;
}

static void hfp_exit(void)
{
	g_dbus_unregister_interface(connection, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);
	bluetooth_unregister_profile(HFP_EXT_PROFILE_PATH);
	bluetooth_unregister_uuid(HFP_AG_UUID);
	ofono_modem_driver_unregister(&hfp_driver);

	g_hash_table_destroy(modem_hash);
	g_hash_table_destroy(hfp_hash);
}

OFONO_PLUGIN_DEFINE(hfp, "Hands-Free Profile Plugins", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT, hfp_init, hfp_exit)
