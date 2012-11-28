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
static struct server *server = NULL;

struct media_endpoint {
	gchar *owner;
	gchar *path;
	guint8 codec;
	guint8 capabilities;
};

struct bt_hfp_address {
	gchar src[18];
	gchar dst[18];
};

struct hfp_data {
	struct hfp_slc_info info;
	gchar *device_address;
	gchar *adapter_address;
	gchar *device_alias;
	gchar *device_path;
	guint8 current_codec;
	DBusMessage *slc_msg;
	GSList *endpoints;
};

static struct media_endpoint *media_endpoint_new(const gchar *owner,
						const gchar *path,
						guint8 codec,
						guint8 capabilities)
{
	struct media_endpoint *endpoint;

	endpoint = g_new0(struct media_endpoint, 1);
	endpoint->owner = g_strdup(owner);
	endpoint->path = g_strdup(path);
	endpoint->codec = codec;
	endpoint->capabilities = capabilities;

	return endpoint;
}

static void media_endpoint_free(gpointer data)
{
	struct media_endpoint *endpoint = data;

	g_free(endpoint->owner);
	g_free(endpoint->path);
	g_free(endpoint);
}

static void media_endpoint_read_codecs(GSList *endpoints, guint8 *codecs,
								size_t size)
{
	GSList *l;
	unsigned int i;

	for (l = endpoints, i = 0; l && i < size; l = g_slist_next(l), i++) {
		struct media_endpoint *endpoint = l->data;
		codecs[i] = endpoint->codec;
	}
}

static void hfp_data_free(gpointer user_data)
{
	struct hfp_data *hfp_data = user_data;

	g_free(hfp_data->device_address);
	g_free(hfp_data->adapter_address);
	g_free(hfp_data->device_alias);
	g_free(hfp_data->device_path);
	g_slist_free_full(hfp_data->endpoints, media_endpoint_free);
	g_free(hfp_data);
}

static struct hfp_data *hfp_data_new(const gchar *adapter_addr,
					const gchar *device_addr,
					const gchar *device_path,
					const gchar *alias)
{
	struct hfp_data *hfp_data;

	hfp_data = g_try_new0(struct hfp_data, 1);
	if (hfp_data == NULL)
		return NULL;

	hfp_data->adapter_address = g_strdup(adapter_addr);
	if (hfp_data->adapter_address == NULL)
		goto free;

	hfp_data->device_address = g_strdup(device_addr);
	if (hfp_data->device_address == NULL)
		goto free;

	hfp_data->device_path = g_strdup(device_path);
	if (hfp_data->device_path == NULL)
		goto free;

	hfp_data->device_alias = g_strdup(alias);
	if (hfp_data->device_alias == NULL)
		goto free;

	return hfp_data;

free:
	hfp_data_free(hfp_data);
	return NULL;
}

static void parse_guint16(DBusMessageIter *iter, gpointer user_data)
{
	guint16 *value = user_data;

	if (dbus_message_iter_get_arg_type(iter) !=  DBUS_TYPE_UINT16)
		return;

	dbus_message_iter_get_basic(iter, value);
}

static void parse_byte(DBusMessageIter *iter, gpointer user_data)
{
	guint8 *value = user_data;

	if (dbus_message_iter_get_arg_type(iter) !=  DBUS_TYPE_BYTE)
		return;

	dbus_message_iter_get_basic(iter, value);
}

static void parse_string(DBusMessageIter *iter, gpointer user_data)
{
	char **str = user_data;
	int arg_type = dbus_message_iter_get_arg_type(iter);

	if (arg_type != DBUS_TYPE_OBJECT_PATH && arg_type != DBUS_TYPE_STRING)
		return;

	dbus_message_iter_get_basic(iter, str);
}

static void parse_media_endpoints(DBusMessageIter *array, gpointer user_data)
{
	GSList **endpoints = user_data;
	struct media_endpoint *endpoint;
	const gchar *path, *owner;
	guint8 codec, capabilities;
	DBusMessageIter dict, variant, entry;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		path = NULL;
		codec = 0x00;
		capabilities = 0x00;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return;

		dbus_message_iter_get_basic(&entry, &owner);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return;

		dbus_message_iter_recurse(&entry, &variant);

		bluetooth_parse_properties(&variant,
				"Path", parse_string, &path,
				"Codec", parse_byte, &codec,
				"Capabilities", parse_byte, &capabilities,
				NULL);

		dbus_message_iter_next(&dict);

		endpoint = media_endpoint_new(owner, path, codec,
							capabilities);
		*endpoints = g_slist_append(*endpoints, endpoint);

		DBG("Media Endpoint %s %s codec:0x%02X Capabilities:0x%02X",
					owner, path, codec, capabilities);
	}
}

static void hfp_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static void bcs_notify(GAtResult *result, gpointer user_data)
{
	struct hfp_data *data = user_data;
	struct hfp_slc_info *info = &data->info;
	GAtResultIter iter;
	GString *str;
	int i, value;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+BCS:"))
		return;

	if (!g_at_result_iter_next_number(&iter, &value))
		return;

	for (i = 0; i < MAX_CODECS && info->codecs[i]; i++) {
		if (info->codecs[i] == value) {
			char buf[64];

			data->current_codec = value;

			snprintf(buf, sizeof(buf), "AT+BCS=%d", value);
			g_at_chat_send(info->chat, buf, NULL, NULL,
							NULL, NULL);
			return;
		}
	}

	str = g_string_new("AT+BAC=");

	for (i = 0; i < MAX_CODECS && info->codecs[i]; i++) {
		g_string_append_printf(str, "%d", info->codecs[i]);
		if (info->codecs[i + 1])
			str = g_string_append(str, ",");
	}

	g_at_chat_send(info->chat, str->str, NULL, NULL, NULL, NULL);
	g_string_free(str, TRUE);
}

static void slc_established(gpointer userdata)
{
	struct ofono_modem *modem = userdata;
	struct hfp_data *data = ofono_modem_get_data(modem);
	struct hfp_slc_info *info = &data->info;
	DBusMessage *msg;

	g_at_chat_register(info->chat, "+BCS:", bcs_notify, FALSE, data, NULL);

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

static int modem_register(const char *device, struct hfp_data *hfp_data,
			int fd, guint16 version, guint8 codecs[MAX_CODECS])
{
	struct ofono_modem *modem;
	char buf[256];

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

	hfp_slc_info_init(&hfp_data->info, version, codecs);

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

	hfp_data = hfp_data_new(adapter_addr, dev_addr, device, alias);
	if (hfp_data == NULL)
		return -ENOMEM;

	g_hash_table_insert(hfp_hash, g_strdup(device), hfp_data);

	return 0;
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
	struct hfp_data *hfp_data;

	if (device == NULL || alias == NULL)
		return;

	hfp_data = g_hash_table_lookup(hfp_hash, device);
	if (hfp_data) {
		g_free(hfp_data->device_alias);
		hfp_data->device_alias = g_strdup(alias);
	}

	modem =	g_hash_table_lookup(modem_hash, device);
	if (modem)
		ofono_modem_set_name(modem, alias);
}

static DBusMessage *profile_new_connection(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct hfp_data *hfp_data;
	const char *device;
	GSList *endpoints = NULL;
	DBusMessageIter entry;
	int fd, err;
	guint16 version = 0x0105, features = 0x0000;
	guint8 codecs[MAX_CODECS];

	DBG("Profile handler NewConnection");

	if (dbus_message_iter_init(msg, &entry) == FALSE)
		goto error;

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_OBJECT_PATH)
		goto error;

	dbus_message_iter_get_basic(&entry, &device);
	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_UNIX_FD)
		goto error;

	dbus_message_iter_get_basic(&entry, &fd);
	if (fd < 0)
		goto error;

	dbus_message_iter_next(&entry);

	bluetooth_parse_properties(&entry,
			"Version", parse_guint16, &version,
			"Features", parse_guint16, &features,
			"MediaEndpoints", parse_media_endpoints, &endpoints,
			NULL);

	if (endpoints == NULL) {
		DBG("Media Endpoint missing");
		goto error;
	}

	hfp_data = g_hash_table_lookup(hfp_hash, device);
	if (hfp_data == NULL) {
		char adapter_address[18], device_address[18];

		/*
		 * Incoming connection notification can arrive before
		 * the Bluetooth device creation finishes.
		 */
		if (bluetooth_get_address(fd, adapter_address,
							device_address) < 0) {
			g_slist_free_full(endpoints, media_endpoint_free);
			return g_dbus_create_error(msg,
					BLUEZ_ERROR_INTERFACE ".Rejected",
					"Invalid arguments in method call");
		}


		hfp_data = hfp_data_new(adapter_address, device_address,
						device, device_address);
		g_hash_table_insert(hfp_hash, g_strdup(device), hfp_data);
	}

	hfp_data->endpoints = endpoints;

	DBG("hfp_data: %p SLC FD: %d Version: 0x%04x Features: 0x%04x",
					hfp_data, fd, version, features);

	memset(codecs, 0, sizeof(codecs));
	media_endpoint_read_codecs(endpoints, codecs, sizeof(codecs));

	err = modem_register(device, hfp_data, fd, version, codecs);
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

static gboolean modem_bt_address_cmp(gpointer key, gpointer value,
							gpointer user_data)
{
	struct ofono_modem *modem = value;
	struct bt_hfp_address *btaddr = user_data;
	struct hfp_data *hfp_data = ofono_modem_get_data(modem);

	if (g_strcmp0(btaddr->src, hfp_data->adapter_address) != 0)
		return FALSE;

	if (g_strcmp0(btaddr->dst, hfp_data->device_address) != 0)
		return FALSE;
	else
		return TRUE;
}

static void sco_server_cb(GIOChannel *io, GError *gerr, gpointer user_data)
{
	struct ofono_modem *modem;
	struct bt_hfp_address btaddr;
	int sk;

	if (gerr) {
		ofono_error("SCO connect: %s", gerr->message);
		goto fail;
	}

	sk = g_io_channel_unix_get_fd(io);
	if (bluetooth_get_address(sk, btaddr.src, btaddr.dst) < 0)
		goto fail;

	modem = g_hash_table_find(modem_hash, modem_bt_address_cmp, &btaddr);
	if (modem == NULL) {
		DBG("Headset not connected, refusing SCO: %s < %s", btaddr.src, btaddr.dst);
		goto fail;
	} else
		DBG("accepted SCO: %s < %s", btaddr.src, btaddr.dst);

	return;
fail:
	g_io_channel_shutdown(io, TRUE, NULL);
}

static int hfp_init(void)
{
	int err;

	if (DBUS_TYPE_UNIX_FD < 0)
		return -EBADF;

	connection = ofono_dbus_get_connection();

	server = bluetooth_register_sco(sco_server_cb, NULL);
	if (server == NULL)
		return -EIO;

	/* Registers External Profile handler */
	if (!g_dbus_register_interface(connection, HFP_EXT_PROFILE_PATH,
					BLUEZ_PROFILE_INTERFACE,
					profile_methods, NULL,
					NULL, NULL, NULL)) {
		ofono_error("Register Profile interface failed: %s",
							HFP_EXT_PROFILE_PATH);
		bluetooth_unregister_sco(server);
		return -EIO;
	}

	err = ofono_modem_driver_register(&hfp_driver);
	if (err < 0) {
		bluetooth_unregister_sco(server);
		return err;
	}

	err = bluetooth_register_uuid(HFP_AG_UUID, &hfp_hf);
	if (err < 0) {
		bluetooth_unregister_sco(server);
		g_dbus_unregister_interface(connection, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);
		ofono_modem_driver_unregister(&hfp_driver);
		return err;
	}

	err = bluetooth_register_profile(HFP_HS_UUID, "hfp_hf",
						HFP_EXT_PROFILE_PATH);
	if (err < 0) {
		bluetooth_unregister_sco(server);
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
	bluetooth_unregister_sco(server);

	g_hash_table_destroy(modem_hash);
	g_hash_table_destroy(hfp_hash);
}

OFONO_PLUGIN_DEFINE(hfp, "Hands-Free Profile Plugins", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT, hfp_init, hfp_exit)
