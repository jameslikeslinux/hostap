/*
 * WPA Supplicant - Layer2 packet handling with Solaris 
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Copyright (c) 2007, Sun Microsystems, Inc.
 * Copyright (c) 2011, James Lee <jlee@thestaticvoid.com>
 *
 * Sun elects to license this software under the BSD license.
 *
 * See README and COPYING for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libdlpi.h>
#include <sys/ethernet.h>
#include <netinet/in.h>

#include "includes.h"
#include "common.h"
#include "eloop.h"
#include "l2_packet.h"

#define IEEE80211_ADDR_LEN	6
#define IEEE80211_MTU_MAX	2304

struct l2_packet_data {
	dlpi_handle_t   dh; /* dlpi handle for EAPOL frames */
	char		ifname[DLPI_LINKNAME_MAX];
	uint8_t		own_addr[IEEE80211_ADDR_LEN];
	void		(*rx_callback)(void *, const unsigned char *,
				       const unsigned char *, size_t);
	void		*rx_callback_ctx;
	int		l2_hdr;
};

static int link_init(struct l2_packet_data *l2)
{
	int retval;
	uint8_t paddr[DLPI_PHYSADDR_MAX];
	size_t paddrlen = sizeof (paddr);

	retval = dlpi_bind(l2->dh, DLPI_ANY_SAP, NULL);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "cannot bind on %s: %s",
			   l2->ifname, dlpi_strerror(retval));
		return -1;
	}

	retval = dlpi_promiscon(l2->dh, DL_PROMISC_SAP);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "cannot enable promiscous"
			   " mode (SAP) on %s: %s",
			   l2->ifname, dlpi_strerror(retval));
		return -1;
	}

	retval = dlpi_get_physaddr(l2->dh, DL_CURR_PHYS_ADDR, paddr,
				   &paddrlen);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "cannot get physical address for %s: %s",
			   l2->ifname, dlpi_strerror(retval));
		return -1;
	}
	if (paddrlen != sizeof (l2->own_addr)) {
		wpa_printf(MSG_ERROR, "physical address for %s is not %d bytes",
			   l2->ifname, sizeof (l2->own_addr));
		return -1;
	}
	os_memcpy(l2->own_addr, paddr, sizeof (l2->own_addr));

	return 0;
}

/*
 * layer2 packet handling.
 */
int l2_packet_get_own_addr(struct l2_packet_data *l2, uint8_t *addr)
{
	os_memcpy(addr, l2->own_addr, sizeof(l2->own_addr));
	return 0;
}

int l2_packet_send(struct l2_packet_data *l2, const uint8_t *dst_addr,
		   uint16_t proto, const uint8_t *buf, size_t buflen)
{
	int retval;
	dlpi_sendinfo_t sendp;

	if (l2->l2_hdr) {
		retval = dlpi_send(l2->dh, NULL, 0, buf, buflen, NULL);
	} else {
		struct l2_ethhdr *eth = os_malloc(sizeof(struct l2_ethhdr) +
						  buflen);
		if (eth == NULL)
			return -1;

		os_memcpy(eth->h_dest, dst_addr, ETH_ALEN);
		os_memcpy(eth->h_source, l2->own_addr, ETH_ALEN);
		eth->h_proto = htons(proto);
		os_memcpy(eth + 1, buf, buflen);
		retval = dlpi_send(l2->dh, NULL, 0, eth,
				   sizeof(struct l2_ethhdr) + buflen, NULL);
		os_free(eth);
	}

	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "l2_packet_send: cannot send "
			   "message on %s: %s",
			   l2->ifname, dlpi_strerror(retval));
		return -1;
	}

	return 0;
}

static void l2_packet_receive(int fd, void *eloop_ctx, void *sock_ctx)
{
	struct l2_packet_data *l2 = eloop_ctx;
	uint64_t packet[IEEE80211_MTU_MAX / sizeof (uint64_t)];
	unsigned char *buf;
	size_t buflen = sizeof (packet);
	struct l2_ethhdr *ethhdr;
	int retval;

	retval = dlpi_recv(l2->dh, NULL, NULL, packet, &buflen, 0, NULL);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "l2_packet_receive: cannot receive "
			   "message on %s: %s",
			   l2->ifname, dlpi_strerror(retval));
		return;
	}

	ethhdr = (struct l2_ethhdr *) packet;

	if (buflen < sizeof (*ethhdr) ||
	    (ntohs(ethhdr->h_proto) != ETHERTYPE_EAPOL &&
	     ntohs(ethhdr->h_proto) != ETHERTYPE_RSN_PREAUTH))
		return;	

	if (l2->l2_hdr) {
		buf = (unsigned char *) ethhdr;
	} else {
		buf = (unsigned char *) (ethhdr + 1);
		buflen -= sizeof(*ethhdr);
	}

	l2->rx_callback(l2->rx_callback_ctx, ethhdr->h_source, buf, buflen);
}

struct l2_packet_data * l2_packet_init(const char *ifname,
	const uint8_t *own_addr, unsigned short protocol,
	void (*rx_callback)(void *, const unsigned char *,
			    const unsigned char *, size_t),
	void *rx_callback_ctx, int l2_hdr)
{
	int retval;
	struct l2_packet_data *l2;

	l2 = (struct l2_packet_data *) os_zalloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return (NULL);

	os_strlcpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;
	l2->l2_hdr = l2_hdr;

   	retval = dlpi_open(l2->ifname, &l2->dh, DLPI_RAW);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "unable to open DLPI link %s: %s",
			   l2->ifname, dlpi_strerror(retval));
		os_free(l2);
		return NULL;
	}

	/* NOTE: link_init() sets l2->own_addr */
	if (link_init(l2) < 0) {
		dlpi_close(l2->dh);
		free(l2);
		return NULL;
	}

	eloop_register_read_sock(dlpi_fd(l2->dh), l2_packet_receive, l2, NULL);

	return l2;
}

void l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

	eloop_unregister_read_sock(dlpi_fd(l2->dh));
	dlpi_close(l2->dh);
	os_free(l2);
}

int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buf, size_t len)
{
	/* Not implemented */
	return -1;
}

void l2_packet_notify_auth_start(struct l2_packet_data *l2)
{
	/* Not implemented */
}
