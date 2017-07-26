//gcc ptm.c -o ptm -lpcap		- build with orig lpcap
//gcc ptm.c -o ptm -L./ -lpcap		- build with fake lpcap

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

//NEEDED PCAP CALLS (28 funcs from like 69) (libtrace_t *trace, libtrace_filter_t *filter)
// - #5

/*
X  1. pcap_findalldevs( &alldevs, errbuf ) == -1 )		- get a list of capture devices
\/ 2. pcap_freealldevs( alldevs );				- free that list

\/ 3. pcap_datalink( descr );					- get the link-layer header type (like ethernet etc)
\/ 4. pcap_datalink_val_to_name( datalink )			- translates a link-layer header type value(from func above) to the corresponding char name
\/ 5. pcap_datalink_val_to_description( datalink )		- translates header type to desc

\/ 6. pcap_close( descr );					- close a capture device or savefile	- # trace_destroy()
\/  7. pcap_open_offline( fileName, errbuf )			- open a saved capture file for reading - # also trace_create()
\/ # 8. descr = pcap_create( devOpts.devName, errbuf )		- create a live capture handle 		- # trace_create()

\/ 9.pcap_set_snaplen( descr, devOpts.snaplen) )		- set the snapshot length for a not-yet-activated capture handle
X  10. pcap_set_buffer_size( descr, devOpts.recvBufSize )	- set the buffer size for a not-yet-activated capture handle
\/ 11. pcap_set_promisc( descr, permisc )			- set promiscuous mode for a not-yet-activated capture handle
X  12. pcap_set_timeout( descr, 1 )				- sets the read timeout that will be used on a capture handle

\/ # 13. pcap_activate( descr )					- start capturing			- # trace_start()

\/14. snaplen = pcap_snapshot( descr )				- returns  the  snapshot  length
\/ 15. pcapFd = pcap_fileno( descr )				- returns the file descriptor  from  which  captured packets are read
X 16. pcap_setnonblock( descr, 0, errbuf )	 (libtrace_t *trace, libtrace_filter_t *filter)		- puts  a  capture  handle into ``non-blocking'' mode
TODO:17. ret = pcap_dispatch( descr, msgCnt , pcap_callback,(Rai_u8 *) this ); - process packets from a live capture or savefile
\/ 18. err = pcap_geterr( descr );				- get libpcap error message text	- # trace_get_err()
X 19. pcap_inject( descr, buff, len );				- send packet
\/ 20. pcap_breakloop( descr );					- force a pcap_dispatch() or pcap_loop() call to return
\/21. pcap_dump_flush( pcapDumper );					- flushes  the  output  buffer  to  the  ``savefile,
\/22. pcap_dump_close( pcapDumper );					- close a savefile being written to
\/23. pcapDumper = pcap_dump_open( descr, newFileBuf )		- open a file to which to write packets

\/24. pcap_lookupnet(devOpts.device(), &netp, &maskp, errbuf)		- find the IPv4 network number and netmask for a device

\/25. pcap_compile( descr, &fp, ( char * ) pcapFilter, 1, maskp ) 	- compile a filter expression
\/# 26. pcap_setfilter( descr, &fp)					- set the filter			- # trace_set_filter()
27. pcap_freecode( &fp );						- free  up  allocated  memory by pcap_compile

28. void pcap_callback(Rai_u8 * args, const struct pcap_pkthdr * pkthdr,const Rai_u8 * packet );	- callback for pcap_loop() or pcap_dispatch()

29. pcap_stats

*/

/* CALLS MISSED IN OUR LIB AND NEEDED BY LIBTRACE:
pcap_dump
pcap_next_ex
pcap_open_dead
pcap_open_live
pcap_perror
pcap_set_immediate_mode
*/


//# pcap_next() - trace_read_packet()


//NEED TO IMPLEMENT IN API:
//------------------------------------------------------------------------------
//1. pcap_create()	- create a live capture handle
//2. pcap_activate()	- activate a capture handle (start capturing)
//3. pcap_lookupdev() 	- will return the first device on that list that is not a ``loopback``
//4. pcap_next() 	- reads the next packet (by calling pcap_dispatch() with a cnt of 1)

//pcap_open_live()	- an old way to start capturing (before libpcap v1.0) - do we need it???

//------------------------------------------------------------------------------

//seq
//1. pcap_create()
//2. pcap_activate()

//pcap_findalldevs()	- obtain list of devices for live capturing

//error codes
#if 0
#define PCAP_ERROR			-1	/* generic error code */
#define PCAP_ERROR_BREAK		-2	/* loop terminated by pcap_breakloop */
#define PCAP_ERROR_NOT_ACTIVATED	-3	/* the capture needs to be activated */
#define PCAP_ERROR_ACTIVATED		-4	/* the operation can't be performed on already activated captures */
#define PCAP_ERROR_NO_SUCH_DEVICE	-5	/* no such device exists */
#define PCAP_ERROR_RFMON_NOTSUP		-6	/* this device doesn't support rfmon (monitor) mode */
#define PCAP_ERROR_NOT_RFMON		-7	/* operation supported only in monitor mode */
#define PCAP_ERROR_PERM_DENIED		-8	/* no permission to open the device */
#define PCAP_ERROR_IFACE_NOT_UP		-9	/* interface isn't up */
#define PCAP_ERROR_CANTSET_TSTAMP_TYPE	-10	/* this device doesn't support setting the time stamp type */
#define PCAP_ERROR_PROMISC_PERM_DENIED	-11	/* you don't have permission to capture in promiscuous mode */
#define PCAP_ERROR_TSTAMP_PRECISION_NOTSUP -12  /* the requested time stamp precision is not supported */
#endif

char errbuf[PCAP_ERRBUF_SIZE];	//256 bytes
int pkts_cnt = 0;

void main(int argc, char *argv[])
{
	int rv;
	char *iface = "wlan0";
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct pcap_stat ps;
	pcap_if_t *interfaces, *temp;
	char error[PCAP_ERRBUF_SIZE];
	//filter
	bpf_u_int32 mask;				/* The netmask of our sniffing device */
	bpf_u_int32 net;				/* The IP of our sniffing device */
	struct bpf_program fp;				/* The compiled filter expression */
	char filter_exp[] = "src host 192.168.0.1";	/* The filter expression */
	int i;

	if (argc == 2)
		iface = argv[1];

	//1. looking for first available device
#if 0
	dev = pcap_lo, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbu, errbufffffffffffffffffffokupdev(errbuf);
	if (!dev) 
	{
		printf("<error> couldn't find default device: %s\n", errbuf);
		exit(1);
	}
	else
		printf("device for capturing found is: %s\n", dev);	//on my pc its eth0 (probably first one)
#endif

/*
example of ifaces list:
0  :  eth0 
1  :  wlan0 
2  :  nflog 
3  :  nfqueue 
4  :  eth2 
5  :  any 
6  :  lo 
*/
	//finding ifaces
	if(pcap_findalldevs(&interfaces, error) == -1)
	{
		printf("error in pcap_findalldevs()\n");
		return;   
	}

	printf("the interfaces on the system are:\n");
	for(temp = interfaces, i = 0; temp; temp = temp->next)
	{
		pcap_addr_t *dev_addr; //interface address that used by pcap_findalldevs()
        	printf("%d  :  %s , %p \n", i++, temp->name, temp->addresses);
		for (dev_addr = temp->addresses; dev_addr != NULL; dev_addr = dev_addr->next) 
		{
        		if (dev_addr->addr && dev_addr->netmask && dev_addr->addr->sa_family == AF_INET) 
			{
            			printf("Found a device [%s] on address %s with netmask %s\n", temp->name,
					inet_ntoa(((struct sockaddr_in *)(dev_addr->addr))->sin_addr),
					inet_ntoa(((struct sockaddr_in *)(dev_addr->netmask))->sin_addr));
            			break;
        		}
    		}
	}

	printf("start capture from iface: %s\n", iface);
	pcap_t *pcap = pcap_create(iface, errbuf);
	if (!pcap)
	{
		printf("<error> pcap_create(): %s\n", errbuf);
		exit(1);
	}

	rv = pcap_activate(pcap);

	if (rv)
	{
		printf("<error ptm> pcap_activate(): %d. %s\n", rv, errbuf);
		exit(1);
	}

	if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "<error ptm> Can't get netmask for device %s\n", iface);
		net = 0;
		mask = 0;
	}

	//setting filter
#if 1
	if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
		return;
	}
	if (pcap_setfilter(pcap, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
		return;
	}
#endif

	while (1)
	{
		/* Grab a packet */
		packet = pcap_next(pcap, &header);
		//TODO: dump of header: macs, eth, tcp/udp, etc
		if (packet)
		{
			printf("Jacked a packet #%d with length of [%d]\n", ++pkts_cnt, header.len);
			if (!rv)
			{
				printf("received: %u, dropped: %u, filtered: %u \n", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
			}
		}
		rv = pcap_stats(pcap, &ps);
	}
}
