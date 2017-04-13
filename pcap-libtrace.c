
//something from libpcap
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libtrace.h>

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

static int pcap_activate_libtrace(pcap_t *handle)
{
        /* Creating and initialising a packet structure to store the packets
         * that we're going to read from the trace. We store all packets here
         * alloc memory for packet and clear its fields */

	//priv is a void* ptr which points to our struct pcap_libtrace
        handle->priv->packet = trace_create_packet();
        if (!handle->priv->packet)
        {
                printf("failed to create packet (storage)\n");
                return NULL;
        }

        handle->priv->trace = trace_create(source);
        if (!handle->priv->trace)
        {
                printf("failed to create trace\n");
                return NULL;
        }
        else
                printf("trace created successfully\n");
}

pcap_t* libtrace_create(const char *device, char *ebuf, int *is_ours)
{
        pcap_t *handle;
        struct pcap_libtrace *ptrace;

        *is_ours = (!strncmp(device, "trace:", 6));
        if (! *is_ours)
                return NULL;

        if (!strncmp(device, "trace:", 6)) 
	{	//we alloc auto space for pcap_t and pcap_libtrace so lets try with 0 here.
                handle = pcap_create_common((device + 6), ebuf, 0); 
                handle->selectable_fd = -1;
                ptrace = handle->priv;
                ptrace->is_netmap = false;	//XXX - not sure we need it
        } 
	else 
	{
                handle = pcap_create_common(device, ebuf, sizeof(struct pcap_linux));
                handle->selectable_fd = -1;
                ptrace = handle->priv;
                ptrace->is_netmap = false;	//XXX - not sure we need it
        }
        if (handle == NULL)
                return NULL;

        handle->activate_op = pcap_activate_libtrace;
        return (handle);
}


