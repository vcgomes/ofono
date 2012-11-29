/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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

#include <errno.h>
#include <glib.h>
#include <gdbus.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/log.h>
#include <ofono/dbus.h>

#include "media.h"

#define MEDIA_ENDPOINT_INTERFACE	"org.bluez.MediaEndpoint"
#define MEDIA_TRANSPORT_INTERFACE	"org.bluez.MediaTransport"

struct media_endpoint {
	gchar *owner;
	gchar *path;
	guint8 codec;
	guint8 capabilities;
};

struct media_transport {
	int fd;
	gchar *path;
	gchar *device_path;
	struct media_endpoint *endpoint;
};

struct media_endpoint *media_endpoint_new(const gchar *owner,
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

void media_endpoint_free(gpointer data)
{
	struct media_endpoint *endpoint = data;

	g_free(endpoint->owner);
	g_free(endpoint->path);
	g_free(endpoint);
}

void media_endpoint_read_codecs(GSList *endpoints, guint8 *codecs, size_t size)
{
	GSList *l;
	unsigned int i;

	for (l = endpoints, i = 0; l && i < size; l = g_slist_next(l), i++) {
		struct media_endpoint *endpoint = l->data;
		codecs[i] = endpoint->codec;
	}
}

struct media_transport *media_transport_create(const gchar *device,
					struct media_endpoint *endpoint,
					int fd)
{
	struct media_transport *transport;

	transport = g_new0(struct media_transport, 1);
	transport->path = g_strdup_printf("%s/%d", device, fd);
	transport->device_path = g_strdup(device);
	transport->fd = fd;
	/* Missing refcounting */
	transport->endpoint = endpoint;

	return transport;
}

void media_transport_remove(struct media_transport *transport)
{
	g_free(transport->device_path);
	g_free(transport->path);
	g_free(transport);
}

static void transport_get_properties(struct media_transport *transport,
						DBusMessageIter *iter)
{
	struct media_endpoint *endpoint = transport->endpoint;
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	ofono_dbus_dict_append(&dict, "Device", DBUS_TYPE_OBJECT_PATH,
						&transport->device_path);

	ofono_dbus_dict_append(&dict, "Codec", DBUS_TYPE_BYTE,
						&endpoint->codec);

	ofono_dbus_dict_append_array(&dict, "Configuration", DBUS_TYPE_BYTE,
						&endpoint->capabilities);

	dbus_message_iter_close_container(iter, &dict);
}

static void media_transport_free(void *user_data)
{
	struct media_transport *transport = user_data;

	media_transport_remove(transport);
}

static DBusMessage *get_properties(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	DBG("");

	return g_dbus_create_error(msg, MEDIA_TRANSPORT_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static DBusMessage *set_property(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	DBG("");

	return g_dbus_create_error(msg, MEDIA_TRANSPORT_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static DBusMessage *acquire(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct media_transport *transport = data;
	struct media_endpoint *endpoint = transport->endpoint;
	const char *accesstype, *sender;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &accesstype,
				DBUS_TYPE_INVALID))
		return g_dbus_create_error(msg, MEDIA_TRANSPORT_INTERFACE
					".InvalidArguments",
					"Invalid arguments in method call");

	sender = dbus_message_get_sender(msg);

	if (!g_str_equal(sender, endpoint->owner))
		return g_dbus_create_error(msg, MEDIA_TRANSPORT_INTERFACE
						".NotAuthorized",
						"Operation not authorized");

	return g_dbus_create_error(msg, MEDIA_TRANSPORT_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static DBusMessage *release(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	DBG("");

	return g_dbus_create_error(msg, MEDIA_TRANSPORT_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static const GDBusMethodTable transport_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_ASYNC_METHOD("Acquire",
			GDBUS_ARGS({ "access_type", "s" }),
			GDBUS_ARGS({ "fd", "h" }, { "mtu_r", "q" },
							{ "mtu_w", "q" } ),
			acquire) },
	{ GDBUS_ASYNC_METHOD("Release",
			GDBUS_ARGS({ "access_type", "s" }), NULL,
			release ) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ },
};

static const GDBusSignalTable transport_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ }
};

int media_transport_register(struct media_transport *transport,
					DBusConnection *conn,
					DBusPendingCallNotifyFunction cb,
					gpointer user_data)
{
	struct media_endpoint *endpoint = transport->endpoint;
	DBusMessage *msg;
	DBusMessageIter iter;
	DBusPendingCall *c;

	if (g_dbus_register_interface(conn, transport->path,
				MEDIA_TRANSPORT_INTERFACE, transport_methods,
				transport_signals, NULL, transport,
				media_transport_free) == FALSE) {
		ofono_error("Could not register transport %s", transport->path);
		return -EIO;
	}

	msg = dbus_message_new_method_call(endpoint->owner, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SetConfiguration");
	if (msg == NULL) {
		ofono_error("Couldn't allocate D-Bus message");
		return -ENOMEM;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							transport->path);

	transport_get_properties(transport, &iter);

	if (!dbus_connection_send_with_reply(conn, msg, &c, -1)) {
		ofono_error("Sending SetConfiguration failed");
		return -EIO;
	}

	dbus_pending_call_set_notify(c, cb, user_data, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);

	return 0;
}

void media_transport_unregister(struct media_transport *transport)
{
	/* ClearConfiguration */
}
