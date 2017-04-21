
//something from libpcap
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <pcap/pcap.h>
#include "pcap-int.h"
#include <libtrace.h>

//I would just leave it here (copy of internal struct in pcap-linux.c)
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


//METHODS FROM LIBPCAP (function pointers inside struct pcap) - SHOULD BE 12.
#if 0
read_op_t read_op; - Method to call to read packets on a live capture.
int (*next_packet_op)(pcap_t *, struct pcap_pkthdr *, u_char **); read packets from a savefile.
typedef int     (*activate_op_t)(pcap_t *);
typedef int     (*can_set_rfmon_op_t)(pcap_t *);
typedef int     (*inject_op_t)(pcap_t *, const void *, size_t);
typedef int     (*setfilter_op_t)(pcap_t *, struct bpf_program *);
typedef int     (*setdirection_op_t)(pcap_t *, pcap_direction_t);
typedef int     (*set_datalink_op_t)(pcap_t *, int);
typedef int     (*getnonblock_op_t)(pcap_t *, char *);
typedef int     (*setnonblock_op_t)(pcap_t *, int, char *);
typedef int     (*stats_op_t)(pcap_t *, struct pcap_stat *);
typedef void    (*cleanup_op_t)(pcap_t *);

#endif

//#1. stub
static int pcap_inject_libtrace(pcap_t *handle, const void *buf, size_t size)
{
        struct pcap_libtrace *handlep = handle->priv;
        int rv = 0;

	debug("[%s() start]\n", __func__);

        return rv;
}

//#2. 
/* Set direction flag: Which packets do we accept on a forwarding
 * single device? IN, OUT or both? */
static int pcap_setdirection_libtrace(pcap_t *handle, pcap_direction_t d)
{
	debug("[%s() start]\n", __func__);

#ifdef HAVE_PF_PACKET_SOCKETS //XXX - where is it defined?
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

//#3.
static int pcap_set_datalink_libtrace(pcap_t *handle, int dlt)
{
        handle->linktype = dlt;
        return 0;
}

//#4. pcap_setnonblock_fd

//#5. pcap_getnonblock_fd

//#6. pcap_cleanup_libtrace
#if 0
struct pcap_libtrace {
        libtrace_t *trace;
        libtrace_packet_t *packet;
        libtrace_out_t *trace_out;
};
#endif

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

//#7. read - this should work instead of pcap_dispatch()
//pcap_dispatch() processes packets from a live capture or ``savefile'' until cnt packets are processed,  the
//end  of  the current bufferful of packets is reached when doing a live capture, the end of the ``savefile''
//is reached when reading from a ``savefile'', pcap_breakloop() is called, or an error  occurs.
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

        debug("[%s() start]\n", __func__);

        for (n = 1; (n <= max_packets) || (max_packets < 0); n++) 
	{
		//trace_read_packet (libtrace_t *trace, libtrace_packet_t *packet)
		//will block until a packet is read (or EOF is reached).
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
			/* fill out pcap_header */
			gettimeofday(&ts, NULL);
			pcap_header.ts = ts;
			//Returns pointer to the start of the layer 2 header
			bp = (u_char *)trace_get_layer2(p->packet, &type, NULL);
			//uint32_t odp_packet_len(odp_packet_t pkt);
			pcap_header.len = trace_get_capture_length(p->packet);
			pcap_header.caplen = pcap_header.len;

			//callback
			callback(userdata, &pcap_header, bp);

			//increase counters
			processed_packets++;

			//check did we receive a notice from pcap_breakloop()
			if (handle->break_loop) 
			{
				handle->break_loop = 0;
				return PCAP_ERROR_BREAK;
                	}
		}
	}

	return processed_packets;
}


//#8. pcap_setfilter
static int pcap_setfilter_libtrace(pcap_t *handle, struct bpf_program *filter)
{

        return 0;
}

//#9. pcap_stats
int pcap_stats_libtrace(pcap_t *handle, struct pcap_stat *ps)
{
        debug("[%s() start]\n", __func__);

        int rv = 0;
	struct pcap_libtrace *p = handle->priv;
        libtrace_stat_t *stat;

        stat = trace_get_statistics(p->trace, NULL);
        if (stat)
        {
                ps->ps_recv = (unsigned int)(stat->received);
                ps->ps_drop = (unsigned int)(stat->dropped);
                ps->ps_ifdrop = (unsigned int)(stat->filtered); //filtered out
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

	int rv = 0;
	struct pcap_libtrace *p = handle->priv;
	const char *device;

	//have "odp:03:00.0"
	device = handle->opt.source;

	debug("[%s() ] p: %p\n", __func__, p);

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
                printf("[%s()]trace created successfully\n",__func__);

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

#if 0
	//check this later
        if (handle->opt.buffer_size != 0) 
	{
                //set the socket buffer size to the specified value.
                if (setsockopt(handle->fd, SOL_SOCKET, SO_RCVBUF, &handle->opt.buffer_size,
                    sizeof(handle->opt.buffer_size)) == -1) 
		{
                        snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "SO_RCVBUF: %s", pcap_strerror(errno));
                        rv = PCAP_ERROR;
			return rv;
                }
        }
#endif

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

	debug("[%s() ] exit with status: %d\n", __func__, rv);

	return rv;
}

pcap_t* libtrace_create(const char *device, char *ebuf, int *is_ours)
{
        pcap_t *handle;
        struct pcap_libtrace *ptrace;

	debug("[%s() start], device: %s\n", __func__, device);

        *is_ours = (!strncmp(device, "odp:", 4));
        if (! *is_ours)
                return NULL;

	//odp:03:00.0 in device
        if (!strncmp(device, "odp:", 4)) 
	{	//we alloc auto space for pcap_t and pcap_libtrace so lets try with 0 here.
		debug("got odp:device \n");
                handle = pcap_create_common((device), ebuf, 0); 
                handle->selectable_fd = -1;
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
        return (handle);
}
