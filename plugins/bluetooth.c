/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010  ProFUSION embedded systems
 *  Copyright (C) 2010  Gustavo F. Padovan <gustavo@padovan.org>
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
#include <gdbus.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/log.h>

#include <btio.h>
#include "bluetooth.h"

static DBusConnection *connection;
static GHashTable *uuid_hash = NULL;
static GHashTable *external_profile_hash = NULL;
static GHashTable *adapter_address_hash = NULL;
static gint bluetooth_refcount;
static GSList *server_list = NULL;
static const char *adapter_any_name = "any";
static char *adapter_any_path = NULL;

#define TIMEOUT 60 /* Timeout for user response (seconds) */

struct server {
	guint8 channel;
	char *sdp_record;
	guint32 handle;
	GIOChannel *io;
	ConnectFunc connect_cb;
	gpointer user_data;
};

struct cb_data {
	struct server *server;
	char *path;
	guint source;
	GIOChannel *io;
};

struct external_profile {
	gboolean registered;
	gchar *uuid;
	gchar *name;
	gchar *object;
};

static void external_profile_free(gpointer user_data)
{
	struct external_profile *eprofile = user_data;

	g_free(eprofile->uuid);
	g_free(eprofile->name);
	g_free(eprofile->object);
	g_free(eprofile);
}

static struct external_profile *external_profile_new(const gchar *uuid,
						const gchar *name,
						const gchar *object)
{
	struct external_profile *eprofile;

	eprofile = g_new0(struct external_profile, 1);
	eprofile->uuid = g_strdup(uuid);
	eprofile->name = g_strdup(name);
	eprofile->object = g_strdup(object);

	return eprofile;
}

static void append_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter value;
	char sig[2] = { type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void dict_append_entry(DBusMessageIter *dict, const char *key, int type,
								void *val)
{
	DBusMessageIter entry;

	if (type == DBUS_TYPE_STRING) {
		const char *str = *((const char **) val);
		if (str == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

void bluetooth_create_path(const char *dev_addr, const char *adapter_addr,
				char *buf, int size)
{
	int i, j;

	for (i = 0, j = 0; adapter_addr[j] && i < size - 1; j++)
		if (adapter_addr[j] >= '0' && adapter_addr[j] <= '9')
			buf[i++] = adapter_addr[j];
		else if (adapter_addr[j] >= 'A' && adapter_addr[j] <= 'F')
			buf[i++] = adapter_addr[j];

	if (i < size - 1)
		buf[i++] = '_';

	for (j = 0; dev_addr[j] && i < size - 1; j++)
		if (dev_addr[j] >= '0' && dev_addr[j] <= '9')
			buf[i++] = dev_addr[j];
		else if (dev_addr[j] >= 'A' && dev_addr[j] <= 'F')
			buf[i++] = dev_addr[j];

	buf[i] = '\0';
}

int bluetooth_send_with_reply(const char *path, const char *interface,
				const char *method, DBusPendingCall **call,
				DBusPendingCallNotifyFunction cb,
				void *user_data, DBusFreeFunction free_func,
				int timeout, int type, ...)
{
	DBusMessage *msg;
	DBusPendingCall *c;
	va_list args;
	int err;

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, path,
						interface, method);
	if (msg == NULL) {
		ofono_error("Unable to allocate new D-Bus %s message", method);
		err = -ENOMEM;
		goto fail;
	}

	va_start(args, type);

	if (!dbus_message_append_args_valist(msg, type, args)) {
		va_end(args);
		err = -EIO;
		goto fail;
	}

	va_end(args);

	if (timeout > 0)
		timeout *= 1000;

	if (!dbus_connection_send_with_reply(connection, msg, &c, timeout)) {
		ofono_error("Sending %s failed", method);
		err = -EIO;
		goto fail;
	}

	if (call != NULL)
		*call = c;

	dbus_pending_call_set_notify(c, cb, user_data, free_func);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);

	return 0;

fail:
	if (free_func && user_data)
		free_func(user_data);

	if (msg)
		dbus_message_unref(msg);

	return err;
}

typedef void (*PropertyHandler)(DBusMessageIter *iter, gpointer user_data);

struct property_handler {
	const char *property;
	PropertyHandler callback;
	gpointer user_data;
};

static gint property_handler_compare(gconstpointer a, gconstpointer b)
{
	const struct property_handler *handler = a;
	const char *property = b;

	return strcmp(handler->property, property);
}

void bluetooth_parse_properties(DBusMessageIter *array, const char *property, ...)
{
	va_list args;
	GSList *prop_handlers = NULL;
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		goto done;

	va_start(args, property);

	while (property != NULL) {
		struct property_handler *handler =
					g_new0(struct property_handler, 1);

		handler->property = property;
		handler->callback = va_arg(args, PropertyHandler);
		handler->user_data = va_arg(args, gpointer);

		property = va_arg(args, const char *);

		prop_handlers = g_slist_prepend(prop_handlers, handler);
	}

	va_end(args);

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;
		GSList *l;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto done;

		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto done;

		dbus_message_iter_recurse(&entry, &value);

		l = g_slist_find_custom(prop_handlers, key,
					property_handler_compare);

		if (l) {
			struct property_handler *handler = l->data;

			handler->callback(&value, handler->user_data);
		}

		dbus_message_iter_next(&dict);
	}

done:
	g_slist_foreach(prop_handlers, (GFunc) g_free, NULL);
	g_slist_free(prop_handlers);
}

static void parse_uuids(DBusMessageIter *array, gpointer user_data)
{
	GSList **uuids = user_data;
	DBusMessageIter value;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &value);

	while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
		const char *uuid;

		dbus_message_iter_get_basic(&value, &uuid);

		*uuids = g_slist_prepend(*uuids, (char *) uuid);

		dbus_message_iter_next(&value);
	}
}

static void parse_string(DBusMessageIter *iter, gpointer user_data)
{
	char **str = user_data;
	int arg_type = dbus_message_iter_get_arg_type(iter);

	if (arg_type != DBUS_TYPE_OBJECT_PATH && arg_type != DBUS_TYPE_STRING)
		return;

	dbus_message_iter_get_basic(iter, str);
}

static void bluetooth_probe(GSList *uuids, const char *path,
				const char *device, const char *adapter,
				const char *alias)
{
	for (; uuids; uuids = uuids->next) {
		struct bluetooth_profile *driver;
		const char *uuid = uuids->data;
		int err;

		driver = g_hash_table_lookup(uuid_hash, uuid);
		if (driver == NULL)
			continue;

		err = driver->probe(path, device, adapter, alias);
		if (err == 0 || err == -EALREADY)
			continue;

		ofono_error("%s probe: %s (%d)", driver->name, strerror(-err),
									-err);
	}
}

static void device_properties_cb(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply;
	const char *path = user_data;
	const char *adapter = NULL;
	const char *adapter_addr = NULL;
	const char *device_addr = NULL;
	const char *alias = NULL;
	DBusMessageIter iter;
	struct DBusError derr;
	GSList *uuids = NULL;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("%s GetAll(\"%s\") replied an error: %s, %s",
					path, FREEDESKTOP_PROPERTIES_INTERFACE,
					derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	DBG("");

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	bluetooth_parse_properties(&iter, "UUIDs", parse_uuids, &uuids,
				"Adapter", parse_string, &adapter,
				"Address", parse_string, &device_addr,
				"Alias", parse_string, &alias, NULL);

	if (adapter)
		adapter_addr = g_hash_table_lookup(adapter_address_hash,
							adapter);

	if (!device_addr || !adapter_addr)
		goto done;

	bluetooth_probe(uuids, path, device_addr, adapter_addr, alias);

done:
	g_slist_free(uuids);
	dbus_message_unref(reply);
}

static void parse_devices(DBusMessageIter *array, gpointer user_data)
{
	DBusMessageIter value;
	GSList **device_list = user_data;

	DBG("");

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &value);

	while (dbus_message_iter_get_arg_type(&value)
			== DBUS_TYPE_OBJECT_PATH) {
		const char *path;

		dbus_message_iter_get_basic(&value, &path);

		*device_list = g_slist_prepend(*device_list, (gpointer) path);

		dbus_message_iter_next(&value);
	}
}

static void get_device_properties(const char *path)
{
	const char *interface = BLUEZ_DEVICE_INTERFACE;

	DBG("Calling %s GetAll(%s)", path, interface);

	bluetooth_send_with_reply(path, FREEDESKTOP_PROPERTIES_INTERFACE,
				"GetAll", NULL, device_properties_cb,
				g_strdup(path), g_free, -1,
				DBUS_TYPE_STRING, &interface,
				DBUS_TYPE_INVALID);
}

static gboolean properties_changed(DBusConnection *conn, DBusMessage *msg,
				void *user_data)
{
	const char *interface, *path, *alias = NULL;
	DBusMessageIter iter;
	GSList *uuids = NULL;

	DBG("");

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return FALSE;

	/* Reading the interface */
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &interface);
	if (g_strcmp0(BLUEZ_DEVICE_INTERFACE, interface) != 0)
		return TRUE;

	if (!dbus_message_iter_next(&iter))
		return FALSE;

	bluetooth_parse_properties(&iter,
			"UUIDs", parse_uuids, &uuids,
			"Alias", parse_string, &alias,
			NULL);

	path = dbus_message_get_path(msg);

	/* We need the full set of properties to be able to
	 * create the modem properly, including Adapter and
	 * Alias, so refetch everything again
	 */
	if (uuids) {
		get_device_properties(path);
		g_slist_free(uuids);
	}

	if (alias) {
		GHashTableIter hash_iter;
		gpointer key, value;

		g_hash_table_iter_init(&hash_iter, uuid_hash);
		while (g_hash_table_iter_next(&hash_iter, &key, &value)) {
			struct bluetooth_profile *profile = value;
			if (profile->set_alias)
				profile->set_alias(path, alias);
		}
	}

	return TRUE;
}

static void adapter_properties_cb(DBusPendingCall *call, gpointer user_data)
{
	const char *path = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusError derr;
	GSList *device_list = NULL;
	GSList *l;
	const char *addr;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("%s GetAll(\"%s\") replied an error: %s, %s",
					path, FREEDESKTOP_PROPERTIES_INTERFACE,
					derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	DBG("");

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	bluetooth_parse_properties(&iter,
					"Devices", parse_devices, &device_list,
					"Address", parse_string, &addr,
					NULL);

	DBG("Adapter Address: %s, Path: %s", addr, path);
	g_hash_table_insert(adapter_address_hash,
				g_strdup(path), g_strdup(addr));

	for (l = device_list; l; l = l->next) {
		const char *device = l->data;

		get_device_properties(device);
	}

done:
	g_slist_free(device_list);
	dbus_message_unref(reply);
}

static void get_adapter_properties(const char *path, const char *handle,
						gpointer user_data)
{
	const char *interface = BLUEZ_ADAPTER_INTERFACE;

	DBG("Calling %s GetAll(%s)", path, interface);

	bluetooth_send_with_reply(path, FREEDESKTOP_PROPERTIES_INTERFACE,
				"GetAll", NULL, adapter_properties_cb,
				g_strdup(path), g_free, -1,
				DBUS_TYPE_STRING, &interface,
				DBUS_TYPE_INVALID);
}

static void remove_record(struct server *server)
{
	DBusMessage *msg;

	if (server->handle == 0)
		return;

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, adapter_any_path,
					BLUEZ_SERVICE_INTERFACE,
					"RemoveRecord");
	if (msg == NULL) {
		ofono_error("Unable to allocate D-Bus RemoveRecord message");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_UINT32, &server->handle,
					DBUS_TYPE_INVALID);
	g_dbus_send_message(connection, msg);

	ofono_info("Unregistered handle for channel %d: 0x%x",
			server->channel, server->handle);
}

static void cb_data_destroy(gpointer data)
{
	struct cb_data *cb_data = data;

	if (cb_data->source != 0)
		g_source_remove(cb_data->source);

	g_free(cb_data->path);
	g_free(cb_data);
}

static void cancel_authorization(struct cb_data *user_data)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, user_data->path,
						BLUEZ_SERVICE_INTERFACE,
						"CancelAuthorization");

	if (msg == NULL) {
		ofono_error("Unable to allocate D-Bus CancelAuthorization"
				" message");
		return;
	}

	g_dbus_send_message(connection, msg);
}

static gboolean client_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct cb_data *cb_data = data;

	cancel_authorization(cb_data);
	cb_data->source = 0;

	return FALSE;
}

static void auth_cb(DBusPendingCall *call, gpointer user_data)
{
	struct cb_data *cb_data = user_data;
	struct server *server = cb_data->server;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	GError *err = NULL;

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("RequestAuthorization error: %s, %s",
				derr.name, derr.message);

		if (dbus_error_has_name(&derr, DBUS_ERROR_NO_REPLY))
			cancel_authorization(cb_data);

		dbus_error_free(&derr);
	} else {
		ofono_info("RequestAuthorization succeeded");

		if (!bt_io_accept(cb_data->io, server->connect_cb,
					server->user_data, NULL, &err)) {
			ofono_error("%s", err->message);
			g_error_free(err);
		}
	}

	dbus_message_unref(reply);
}

static void new_serial_connection(GIOChannel *io, gpointer user_data)
{
	struct server *server = user_data;
	struct cb_data *cbd;
	const char *addr;
	GError *err = NULL;
	char laddress[18], raddress[18];
	guint8 channel;
	GHashTableIter iter;
	gpointer key, value;
	const char *path;

	bt_io_get(io, BT_IO_RFCOMM, &err, BT_IO_OPT_SOURCE, laddress,
					BT_IO_OPT_DEST, raddress,
					BT_IO_OPT_CHANNEL, &channel,
					BT_IO_OPT_INVALID);
	if (err) {
		ofono_error("%s", err->message);
		g_error_free(err);
		return;
	}

	ofono_info("New connection for %s on channel %u from: %s,", laddress,
							channel, raddress);

	path = NULL;
	g_hash_table_iter_init(&iter, adapter_address_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		if (g_str_equal(laddress, value) == TRUE) {
			path = key;
			break;
		}
	}

	if (path == NULL)
		return;

	cbd = g_try_new0(struct cb_data, 1);
	if (cbd == NULL) {
		ofono_error("Unable to allocate client cb_data structure");
		return;
	}

	cbd->path = g_strdup(path);
	cbd->server = server;
	cbd->io = io;

	addr = raddress;

	if (bluetooth_send_with_reply(path, BLUEZ_SERVICE_INTERFACE,
					"RequestAuthorization", NULL,
					auth_cb, cbd, cb_data_destroy,
					TIMEOUT, DBUS_TYPE_STRING, &addr,
					DBUS_TYPE_UINT32, &server->handle,
					DBUS_TYPE_INVALID) < 0) {
		ofono_error("Request Bluetooth authorization failed");
		return;
	}

	ofono_info("RequestAuthorization(%s, 0x%x)", raddress, server->handle);

	cbd->source = g_io_add_watch(io, G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					client_event, cbd);
}

static void remove_service_handle(gpointer data, gpointer user_data)
{
	struct server *server = data;

	server->handle = 0;
}

static void add_record_cb(DBusPendingCall *call, gpointer user_data)
{
	struct server *server = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("Replied with an error: %s, %s",
					derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	dbus_message_get_args(reply, NULL, DBUS_TYPE_UINT32, &server->handle,
					DBUS_TYPE_INVALID);

	ofono_info("Registered handle for channel %d: 0x%x",
			server->channel, server->handle);

done:
	dbus_message_unref(reply);
}

static void add_record(gpointer data, gpointer user_data)
{
	struct server *server = data;

	if (server->sdp_record == NULL)
		return;

	bluetooth_send_with_reply(adapter_any_path,
					BLUEZ_SERVICE_INTERFACE, "AddRecord",
					NULL, add_record_cb, server, NULL, -1,
					DBUS_TYPE_STRING, &server->sdp_record,
					DBUS_TYPE_INVALID);
}

static void find_adapter_cb(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	const char *path;

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("Replied with an error: %s, %s",
					derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID);

	g_free(adapter_any_path);
	adapter_any_path = g_strdup(path);

	g_slist_foreach(server_list, (GFunc) add_record, NULL);

done:
	dbus_message_unref(reply);
}

static gboolean adapter_added(DBusConnection *conn, DBusMessage *message,
				void *user_data)
{
	const char *path;

	dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);

	get_adapter_properties(path, NULL, NULL);

	return TRUE;
}

static void bluetooth_remove(gpointer key, gpointer value, gpointer user_data)
{
	struct bluetooth_profile *profile = value;

	profile->remove(user_data);
}

static gboolean adapter_removed(DBusConnection *conn,
				DBusMessage *message, void *user_data)
{
	const char *path;

	if (dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID) == FALSE)
		return FALSE;

	g_hash_table_foreach(uuid_hash, bluetooth_remove, (gpointer) path);
	g_hash_table_remove(adapter_address_hash, path);

	return TRUE;
}

static gboolean device_removed(DBusConnection *conn,
				DBusMessage *message, void *user_data)
{
	const char *path;

	if (dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID) == FALSE)
		return FALSE;

	g_hash_table_foreach(uuid_hash, bluetooth_remove, (gpointer) path);

	return TRUE;
}

static void parse_adapters(DBusMessageIter *array)
{
	DBusMessageIter value;

	DBG("");

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &value);

	while (dbus_message_iter_get_arg_type(&value)
			== DBUS_TYPE_OBJECT_PATH) {
		const char *path;

		dbus_message_iter_get_basic(&value, &path);

		get_adapter_properties(path, NULL, NULL);

		dbus_message_iter_next(&value);
	}
}

static void adapters_objects_cb(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply;
	DBusError derr;
	DBusMessageIter array, variant;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("Get(\"%s\", \"Adapters\") replied an error: %s, "
					"%s", FREEDESKTOP_PROPERTIES_INTERFACE,
					derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	if (dbus_message_iter_init(reply, &variant) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_VARIANT)
		goto done;

	dbus_message_iter_recurse(&variant, &array);

	parse_adapters(&array);

done:
	dbus_message_unref(reply);
}

static void profile_register_cb(DBusPendingCall *call, gpointer user_data)
{
	struct external_profile *eprofile = user_data;
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("RegisterProfile() replied an error: %s, %s",
						derr.name, derr.message);
		dbus_error_free(&derr);
		eprofile->registered = FALSE;
		goto done;
	}

	DBG("");

done:
	dbus_message_unref(reply);
}

static int external_profile_register(const char *uuid, const char *name,
					const char *object, gpointer user_data)
{
	DBusMessageIter iter, dict;
	DBusPendingCall *c;
	DBusMessage *msg;

	DBG("Bluetooth: Registering %s (%s) profile", uuid, name);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, "/org/bluez",
			BLUEZ_PROFILE_MGMT_INTERFACE, "RegisterProfile");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter,
			DBUS_TYPE_OBJECT_PATH, &object);
	dbus_message_iter_append_basic(&iter,
			DBUS_TYPE_STRING, &uuid);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
	dict_append_entry(&dict, "Name", DBUS_TYPE_STRING, &name);

	dbus_message_iter_close_container(&iter, &dict);

	if (!dbus_connection_send_with_reply(connection, msg, &c, -1)) {
		ofono_error("Sending RegisterProfile failed");
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_pending_call_set_notify(c, profile_register_cb, user_data, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);

	return 0;
}

static void external_profile_foreach(gpointer key, gpointer value,
							gpointer user_data)
{
	struct external_profile *eprofile = value;
	const char *uuid = key;

	if (eprofile->registered)
		return;

	if (external_profile_register(uuid, eprofile->name, eprofile->object,
								eprofile) < 0)
		return;

	eprofile->registered = TRUE;
}
static void external_profile_set_unregistered(gpointer key, gpointer value,
							gpointer user_data)
{
	struct external_profile *eprofile = value;

	eprofile->registered = FALSE;
}

static void bluetooth_connect(DBusConnection *conn, void *user_data)
{
	const char *interface = BLUEZ_MANAGER_INTERFACE;
	const char *property = "Adapters";

	bluetooth_send_with_reply("/", FREEDESKTOP_PROPERTIES_INTERFACE, "Get",
				NULL, adapters_objects_cb, NULL, NULL, -1,
				DBUS_TYPE_STRING, &interface,
				DBUS_TYPE_STRING, &property,
				DBUS_TYPE_INVALID);

	bluetooth_send_with_reply("/", BLUEZ_MANAGER_INTERFACE, "FindAdapter",
				NULL, find_adapter_cb, NULL, NULL, -1,
				DBUS_TYPE_STRING, &adapter_any_name,
				DBUS_TYPE_INVALID);

	g_hash_table_foreach(external_profile_hash, external_profile_foreach, NULL);
}

static void bluetooth_disconnect(DBusConnection *conn, void *user_data)
{
	if (uuid_hash == NULL)
		return;

	g_hash_table_foreach(uuid_hash, bluetooth_remove, NULL);
	g_hash_table_foreach(external_profile_hash,
				external_profile_set_unregistered, NULL);

	g_slist_foreach(server_list, (GFunc) remove_service_handle, NULL);
}

static guint bluetooth_watch;
static guint adapter_added_watch;
static guint adapter_removed_watch;
static guint device_removed_watch;
static guint property_watch;

static void bluetooth_ref(void)
{
	if (bluetooth_refcount > 0)
		goto increment;

	connection = ofono_dbus_get_connection();

	bluetooth_watch = g_dbus_add_service_watch(connection, BLUEZ_SERVICE,
					bluetooth_connect,
					bluetooth_disconnect, NULL, NULL);

	adapter_added_watch = g_dbus_add_signal_watch(connection, BLUEZ_SERVICE,
						NULL, BLUEZ_MANAGER_INTERFACE,
						"AdapterAdded",
						adapter_added, NULL, NULL);

	adapter_removed_watch = g_dbus_add_signal_watch(connection,
						BLUEZ_SERVICE, NULL,
						BLUEZ_MANAGER_INTERFACE,
						"AdapterRemoved",
						adapter_removed, NULL, NULL);

	device_removed_watch = g_dbus_add_signal_watch(connection,
						BLUEZ_SERVICE, NULL,
						BLUEZ_ADAPTER_INTERFACE,
						"DeviceRemoved",
						device_removed, NULL, NULL);

	property_watch = g_dbus_add_signal_watch(connection,
						BLUEZ_SERVICE, NULL,
						FREEDESKTOP_PROPERTIES_INTERFACE,
						"PropertiesChanged",
						properties_changed, NULL, NULL);

	if (bluetooth_watch == 0 || adapter_added_watch == 0 ||
			adapter_removed_watch == 0 || property_watch == 0) {
		goto remove;
	}

	uuid_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, NULL);

	external_profile_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, external_profile_free);

	adapter_address_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, g_free);

increment:
	g_atomic_int_inc(&bluetooth_refcount);

	return;

remove:
	g_dbus_remove_watch(connection, bluetooth_watch);
	g_dbus_remove_watch(connection, adapter_added_watch);
	g_dbus_remove_watch(connection, adapter_removed_watch);
	g_dbus_remove_watch(connection, property_watch);
}

static void bluetooth_unref(void)
{
	if (g_atomic_int_dec_and_test(&bluetooth_refcount) == FALSE)
		return;

	g_free(adapter_any_path);
	adapter_any_path = NULL;

	g_dbus_remove_watch(connection, bluetooth_watch);
	g_dbus_remove_watch(connection, adapter_added_watch);
	g_dbus_remove_watch(connection, adapter_removed_watch);
	g_dbus_remove_watch(connection, property_watch);

	g_hash_table_destroy(uuid_hash);
	g_hash_table_destroy(external_profile_hash);
	g_hash_table_destroy(adapter_address_hash);
}

void bluetooth_get_properties()
{
	g_hash_table_foreach(adapter_address_hash,
				(GHFunc) get_adapter_properties, NULL);
}

int bluetooth_register_uuid(const char *uuid, struct bluetooth_profile *profile)
{
	bluetooth_ref();

	g_hash_table_insert(uuid_hash, g_strdup(uuid), profile);

	g_hash_table_foreach(adapter_address_hash,
				(GHFunc) get_adapter_properties, NULL);

	return 0;
}

void bluetooth_unregister_uuid(const char *uuid)
{
	g_hash_table_remove(uuid_hash, uuid);

	bluetooth_unref();
}

int bluetooth_register_profile(const char *uuid, const char *name,
							const char *object)
{
	struct external_profile *eprofile;
	int err;

	bluetooth_ref();

	eprofile = external_profile_new(uuid, name, object);
	err = external_profile_register(uuid, name, object, eprofile);
	if (err < 0) {
		external_profile_free(eprofile);
		bluetooth_unref();
		return -EIO;
	}

	eprofile->registered = TRUE;
	g_hash_table_insert(external_profile_hash, g_strdup(uuid), eprofile);

	return 0;
}

static void unregister_profile_cb(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("UnregisterProfile() replied an error: %s, %s",
						derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	DBG("");

done:
	dbus_message_unref(reply);
}

void bluetooth_unregister_profile(const char *object)
{
	struct external_profile *eprofile;
	DBusMessageIter iter;
	DBusPendingCall *c;
	DBusMessage *msg;

	DBG("Bluetooth: Unregistering profile %s", object);

	eprofile = g_hash_table_lookup(external_profile_hash, object);
	if (eprofile == NULL)
		return;

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, "/org/bluez",
			BLUEZ_PROFILE_MGMT_INTERFACE, "UnregisterProfile");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object);

	if (!dbus_connection_send_with_reply(connection, msg, &c, -1)) {
		ofono_error("Sending RegisterProfile failed");
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(c, unregister_profile_cb, NULL, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);

	g_hash_table_remove(external_profile_hash, object);

	bluetooth_unref();
}

struct server *bluetooth_register_serial(guint8 channel, const char *sdp_record,
					ConnectFunc cb, gpointer user_data)
{
	struct server *server;
	GError *err = NULL;

	server = g_try_new0(struct server, 1);
	if (!server)
		return NULL;

	server->channel = channel;

	server->io = bt_io_listen(BT_IO_RFCOMM, NULL, new_serial_connection,
					server, NULL, &err,
					BT_IO_OPT_CHANNEL, server->channel,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
					BT_IO_OPT_INVALID);
	if (server->io == NULL) {
		g_error_free(err);
		g_free(server);
		return NULL;
	}

	bluetooth_ref();

	if (sdp_record != NULL)
		server->sdp_record = g_strdup(sdp_record);

	server->connect_cb = cb;
	server->user_data = user_data;

	server_list = g_slist_prepend(server_list, server);

	if (adapter_any_path != NULL)
		add_record(server, NULL);

	return server;
}

void bluetooth_unregister_serial(struct server *server)
{
	server_list = g_slist_remove(server_list, server);

	remove_record(server);

	if (server->io != NULL) {
		g_io_channel_shutdown(server->io, TRUE, NULL);
		g_io_channel_unref(server->io);
		server->io = NULL;
	}

	g_free(server->sdp_record);
	g_free(server);

	bluetooth_unref();
}

static void sco_confirm_cb(GIOChannel *io, gpointer user_data)
{
	struct server *server = user_data;
	GError *gerr = NULL;

	if (!bt_io_accept(io, server->connect_cb, user_data, NULL, &gerr)) {
		ofono_error("bt_io_accept() failed: %s\n", gerr->message);
		server->connect_cb(io, gerr, server->user_data);
		g_clear_error(&gerr);
		return;
	}
}

struct server *bluetooth_register_sco(ConnectFunc cncb, gpointer user_data)
{
	struct server *server;

	server = g_try_new0(struct server, 1);
	if (!server)
		return NULL;

	server->io = bt_io_listen(BT_IO_SCO, NULL, sco_confirm_cb,
					server, NULL, NULL, BT_IO_OPT_INVALID);
	if (server->io == NULL) {
		g_free(server);
		return NULL;
	}

	bluetooth_ref();

	server->connect_cb = cncb;
	server->user_data = user_data;

	server_list = g_slist_prepend(server_list, server);

	return server;
}

void bluetooth_unregister_sco(struct server *server)
{
	server_list = g_slist_remove(server_list, server);

	if (server->io != NULL) {
		g_io_channel_shutdown(server->io, TRUE, NULL);
		g_io_channel_unref(server->io);
		server->io = NULL;
	}

	g_free(server);

	bluetooth_unref();
}

int bluetooth_get_address(int fd, char *adapter_address, char *device_address)
{
	struct sockaddr_rc saddr;
	socklen_t alen;

	alen = sizeof(saddr);

	if (adapter_address) {
		if (getsockname(fd, (struct sockaddr *)&saddr, &alen) < 0)
			return -errno;

		ba2str(&saddr.rc_bdaddr, adapter_address);
	}

	if (device_address) {
		if (getpeername(fd, (struct sockaddr *)&saddr, &alen) < 0)
			return -errno;

		ba2str(&saddr.rc_bdaddr, device_address);
	}

	return 0;
}

OFONO_PLUGIN_DEFINE(bluetooth, "Bluetooth Utils Plugins", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT, NULL, NULL)
