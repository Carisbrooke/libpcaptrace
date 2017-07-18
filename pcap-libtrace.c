/*
 * Copyright (c) 2017 Intelligent Compute LTD
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * libtrace support implementation for linux platform
 * by Andrii Guriev <bearrailgun@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap/pcap.h>
#include "pcap-int.h"
#include <libtrace.h>

//----- OPTIONS -----
//#define OPTION_VERBOSE_STATS
//#define OPTION_HEXDUMP_PACKETS

/*
 * Private data for capturing on Linux SOCK_PACKET or PF_PACKET sockets.
 */
struct pcap_linux {
        u_int   packets_read;   /* count of packets read with recvfrom() */
        long    proc_dropped;   /* packets reported dropped by /proc/net/dev */
        struct pcap_stat stat;

        char    *device;        /* device name */
        int     filter_in_userland; /* must filter in userland */
        int     blocks_to_filter_in_userland;
        int     must_do_on_close; /* stuff we must do when we close */
        int     timeout;        /* timeout for buffering */
        int     sock_packet;    /* using Linux 2.0 compatible interface */
        int     cooked;         /* using SOCK_DGRAM rather than SOCK_RAW */
        int     ifindex;        /* interface index of device we're bound to */
        int     lo_ifindex;     /* interface index of the loopback device */
        bpf_u_int32 oldmode;    /* mode to restore when turning monitor mode off */
        char    *mondevice;     /* mac80211 monitor device we created */
        u_char  *mmapbuf;       /* memory-mapped region pointer */
        size_t  mmapbuflen;     /* size of region */
        int     vlan_offset;    /* offset at which to insert vlan tags; if -1, don't insert */
        u_int   tp_version;     /* version of tpacket_hdr for mmaped ring */
        u_int   tp_hdrlen;      /* hdrlen of tpacket_hdr for mmaped ring */
        u_char  *oneshot_buffer; /* buffer for copy of packet */
#ifdef HAVE_TPACKET3
        unsigned char *current_packet; /* Current packet within the TPACKET_V3 block. Move to next block if NULL. */
        int packets_left; /* Unhandled packets left within the block from previous call to pcap_read_linux_mmap_v3 in case of TPACKET_V3. */
#endif
};

#ifdef OPTION_HEXDUMP_PACKETS
void hexdump(void *addr, unsigned int size)
{
        unsigned int i;
        /* move with 1 byte step */
        unsigned char *p = (unsigned char*)addr;

        //printf("addr : %p \n", addr);

        if (!size)
        {
                printf("bad size %u\n",size);
                return;
        }

        for (i = 0; i < size; i++)
        {
                if (!(i % 16))    /* 16 bytes on line */
                {
                        if (i)
                                printf("\n");
                        printf("0x%lX | ", (long unsigned int)(p+i)); /* print addr at the line begin */
                }
                printf("%02X ", p[i]); /* space here */
        }

        printf("\n");
}
#endif

static int pcap_inject_libtrace(pcap_t *handle, const void *buf, size_t size)
{
        struct pcap_libtrace *handlep = handle->priv;
        int rv = 0;

	debug("[%s() start]\n", __func__);

        return rv;
}

/* Set direction flag: Which packets do we accept on a forwarding
 * single device? IN, OUT or both? */
static int pcap_setdirection_libtrace(pcap_t *handle, pcap_direction_t d)
{
	debug("[%s() start]\n", __func__);

#ifdef HAVE_PF_PACKET_SOCKETS
        struct pcap_linux *handlep = handle->priv;

        if (!handlep->sock_packet) {
                handle->direction = d;
                return 0;
        }
#endif
        /*
         * We're not using PF_PACKET sockets, so we can't determine
         * the direction of the packet.
         */
        snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
            "Setting direction is not supported on SOCK_PACKET sockets");
        return -1;
}

static int pcap_set_datalink_libtrace(pcap_t *handle, int dlt)
{
	debug("pcap_set_datalink_libtrace() setting type: %d\n", dlt);
        handle->linktype = dlt;
        return 0;
}

static void pcap_cleanup_libtrace(pcap_t *handle)
{
        debug("[%s() start]\n", __func__);

        struct pcap_libtrace *p = (struct pcap_libtrace *)handle->priv;

        if (p->packet)
                trace_destroy_packet(p->packet);
        if (p->trace)
                trace_destroy(p->trace);
        free(p);

	pcap_cleanup_live_common(handle);
}

//routine which works when pcap_dispatch() called
static int pcap_read_libtrace(pcap_t *handle, int max_packets, pcap_handler callback, u_char *userdata)
{
        int rv;
	struct pcap_libtrace *p = handle->priv;
	struct pcap_pkthdr pcap_header;
	u_char *bp;
	libtrace_linktype_t type;
        struct timeval ts;
	long n = 1;
	int processed_packets = 0;

        debug("[%s() start] max_packets: %d \n", __func__, max_packets);

        for (n = 1; (n <= max_packets) || (max_packets < 0); n++) 
	{
		//will block until a packet will be read (or EOF is reached).
		//returns number of bytes read, 0 if EOF, -1 if error.
		rv = trace_read_packet(p->trace, p->packet);
		if (rv == 0)
		{
			printf("EOF, no packets\n");
			return rv;
		}
		else if (rv < 0)
		{
			printf("error reading packet\n");
			rv = -1; return rv;	//according to man we return -1 on error
		}
		else
		{
#ifdef OPTION_HEXDUMP_PACKETS
			printf("have a packet at %p with %d bytes\n",p->packet->payload, rv);
			hexdump(p->packet->payload, rv);
#endif
			//filtering
			if (p->filter)
			{
				rv = trace_apply_filter(p->filter, p->packet);
				if (rv == -1)
				{
					printf("error applying filter\n");
					rv = -1; return rv;
				}
				else if (rv == 0)
				{
					p->filtered_pkts++; //increase counter of filtered out packets
					debug("packet didn't match the filter. skipping\n");
					continue;
				}
			}

			/* fill out pcap_header */
			gettimeofday(&ts, NULL);
			pcap_header.ts = ts;
			//Returns pointer to the start of the layer 2 header
			bp = (u_char *)trace_get_layer2(p->packet, &type, NULL);
			pcap_header.len = trace_get_capture_length(p->packet);
			pcap_header.caplen = pcap_header.len;

			/*printf("pointer to a packet by trace_get_layer2() is : %p. orig payload: %p, size: %u \n",
				 bp, p->packet->payload, pcap_header.len);*/
			callback(userdata, &pcap_header, bp);

			p->accepted_pkts++;

			//check did we receive a notice from pcap_breakloop()
			if (handle->break_loop) 
			{
				handle->break_loop = 0;
				return PCAP_ERROR_BREAK;
                	}
		}
	}

        debug("[%s() exit] processed_packets: %d \n", __func__, processed_packets);
	return processed_packets;
}

static int pcap_setfilter_libtrace(pcap_t *handle, struct bpf_program *filter)
{
	libtrace_filter_t* tracefilter;
	struct pcap_libtrace *p = handle->priv;

        debug("[%s() start]\n", __func__);

	tracefilter = trace_create_filter_from_bytecode(filter->bf_insns, filter->bf_len);
	if (!tracefilter)
		return -1;
	else
	{
		p->filter = tracefilter; //saved filter to our struct
		debug("[%s() ] filter set and saved successfully\n", __func__);
	}

        return 0;
}

int pcap_stats_libtrace(pcap_t *handle, struct pcap_stat *ps)
{
        int rv = 0;
	struct pcap_libtrace *p = handle->priv;
        libtrace_stat_t *stat;

        debug("[%s() start]\n", __func__);

        stat = trace_get_statistics(p->trace, NULL);
        if (stat)
        {
                ps->ps_recv = p->accepted_pkts;   		//yes, we provide counter of accepted packets here
                //ps->ps_recv = (unsigned int)(stat->accepted); //orig libtrace stats
                ps->ps_drop = (unsigned int)(stat->dropped);    //dropped because lack of buffer space
                ps->ps_ifdrop = p->filtered_pkts; 		//filtered out packets

#ifdef OPTION_VERBOSE_STATS
/*
 * original libtrace stats
		printf("accepted: %u \t", stat->accepted);
		printf("filtered: %u \t", stat->filtered);
		printf("received: %u \t", stat->received);
		printf("dropped: %u \t", stat->dropped);
		printf("captured: %u \n", stat->captured);
*/
		//our converted stats
		printf("received: %u, dropped: %u, filtered: %u \n", ps->ps_recv, ps->ps_drop, ps->ps_ifdrop);
#endif
        }
        else
                rv = -1;

        return rv;
}

int pcap_activate_libtrace(pcap_t *handle)
{
        /* Creating and initialising a packet structure to store the packets
         * that we're going to read from the trace. We store all packets here
         * alloc memory for packet and clear its fields */

	static int activated = 0;
	int rv = 0;
	struct pcap_libtrace *p = handle->priv;
	const char *device;

	debug("[%s() start] activated: %d\n", __func__, activated);

	if (activated)
		return rv;
	else
		activated = 1;

	device = handle->opt.destination;

	//priv is a void* ptr which points to our struct pcap_libtrace
        p->packet = trace_create_packet();
        if (!p->packet)
        {
                printf("failed to create packet (storage)\n");
                return -1;
        }

	debug("[%s() ] creating trace for device: %s\n", __func__, device);
        p->trace = trace_create(device);
        if (!p->trace)
        {
                printf("failed to create trace\n");
                return -1;
        }
        else
                debug("[%s()]trace created successfully\n",__func__);

	//setting functions
        handle->inject_op = pcap_inject_libtrace;
        handle->setdirection_op = pcap_setdirection_libtrace;
        handle->set_datalink_op = pcap_set_datalink_libtrace;
        handle->setnonblock_op = pcap_setnonblock_fd; /* Not our function */
        handle->getnonblock_op = pcap_getnonblock_fd; /* Not our function */
        handle->cleanup_op = pcap_cleanup_libtrace;
        handle->read_op = pcap_read_libtrace;
        handle->setfilter_op = pcap_setfilter_libtrace;
        handle->stats_op = pcap_stats_libtrace;

        handle->buffer = malloc(handle->bufsize + handle->offset);
        if (!handle->buffer) 
	{
                snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "malloc: %s", pcap_strerror(errno));
                rv = PCAP_ERROR;
		return rv;
        }

        handle->selectable_fd = handle->fd;

	//here we start
	debug("[%s() ] starting trace for device: %s\n", __func__, device);
	rv = trace_start(p->trace);

	debug("[%s() end] exit with status: %d\n", __func__, rv);

	return rv;
}

//env var should be in form: LIBPCAPTRACE_IFACE=enp3s0,odp:03:00.0
pcap_t* libtrace_create(const char *device, char *ebuf, int *is_ours)
{
        pcap_t *handle = NULL;
        struct pcap_libtrace *ptrace;
	char *env;

	debug("[%s() start], device: %s\n", __func__, device);

	env = getenv("LIBPCAPTRACE_IFACE");
	debug("our env var is: [%s]\n", env);
	if (env)
	{	//if we found let say enp3s0 in env variable before ','
		*is_ours = (!strcmp(device, strtok(strdup(env), ",")));
		debug("matching our device [%s] with first half of env variable [%s]. ", device, env);
		debug("%s\n", *is_ours ? "matched" : "not matched");
	}
        if (! *is_ours)
                return NULL;

	if (strstr(env, "odp:"))
	{	//we alloc auto space for pcap_t and pcap_libtrace so lets try with 0 here.
		debug("got odp:device \n");
                handle = pcap_create_common((device), ebuf, 0); 
                handle->selectable_fd = -1;
		handle->linktype = 1;	//set linktype to ETHERNET
                ptrace = handle->priv;
        }
	else if (strstr(env, "kafka:"))
	{
		debug("got kafka:device \n");
                handle = pcap_create_common((device), ebuf, 0);
                handle->selectable_fd = -1;
		handle->linktype = 1;	//set linktype to ETHERNET
                ptrace = handle->priv;
	}
	else 
	{
                handle = pcap_create_common(device, ebuf, sizeof(struct pcap_linux));
                handle->selectable_fd = -1;
                ptrace = handle->priv;
        }
        if (handle == NULL)
                return NULL;

        handle->activate_op = pcap_activate_libtrace;

	debug("[%s() end], handle: %p\n", __func__, handle);

        return (handle);
}
