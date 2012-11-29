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
	gchar *path;
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
	/* Missing refcounting */
	transport->endpoint = endpoint;

	return transport;
}

void media_transport_remove(struct media_transport *transport)
{
	g_free(transport->path);
	g_free(transport);
}

int media_transport_register(struct media_transport *transport,
					DBusConnection *conn,
					DBusPendingCallNotifyFunction cb,
					gpointer user_data)
{
	struct media_endpoint *endpoint = transport->endpoint;
	DBusMessage *msg;
	DBusPendingCall *c;

	/* Register transport object */

	msg = dbus_message_new_method_call(endpoint->owner, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SetConfiguration");

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


