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

struct media_endpoint;
struct media_transport;

struct media_endpoint *media_endpoint_new(const gchar *owner,
						const gchar *path,
						guint8 codec,
						guint8 capabilities);

void media_endpoint_free(gpointer data);

void media_endpoint_read_codecs(GSList *endpoints, guint8 *codecs, size_t size);

struct media_transport *media_transport_create(const gchar *device,
					struct media_endpoint *endpoint,
					int fd);

void media_transport_remove(struct media_transport *transport);

int media_transport_register(struct media_transport *transport,
					DBusConnection *conn,
					DBusPendingCallNotifyFunction cb,
					gpointer user_data);

void media_transport_unregister(struct media_transport *transport);
