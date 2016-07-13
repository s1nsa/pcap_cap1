#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header


struct sockaddr_in source,dest;

int main()
{
   pcap_t *handle;			/* Session handle */
   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program fp;		/* The compiled filter */
   char filter_exp[]="";	/* The filter expression */
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */

   /* Define the device */
   dev = pcap_lookupdev(errbuf);
   if (dev == NULL) {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return(2);
   }
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }
   /* Compile and apply the filter */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   /* Grab a packet */
   while(1)
   {
       struct pcap_pkthdr *header;
       const u_char *packet;


       const int res = pcap_next_ex(handle, &header, &packet);

       if(res<0)
       {
             break;
       }
       if(res==0)
       {
             continue;
       }

       struct ethhdr * eth = (struct ethhdr*) packet;


       short type = ntohs(eth->h_proto);
       if(type == ETHERTYPE_IP)
       {
           struct iphdr * iph = (struct iphdr *)(packet+ sizeof(struct ethhdr));
           unsigned short iphdrlen;

           iphdrlen = iph->ihl*4;


           memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph->saddr;

            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = iph->daddr;



           if(iph->protocol==IPPROTO_TCP)
           {
             printf("--------------------------------------------\n");
             printf("Ethernet Header\n");
             printf("Dest Mac addr : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
             printf("Src Mac addr : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
             printf("\n");
             printf("IP Header\n");
             printf("Src ip : %s\n",inet_ntoa(source.sin_addr) );
             printf("Dest ip : %s\n",inet_ntoa(dest.sin_addr) );
             printf("\n");


             struct tcphdr * tph = (struct tcphdr *)(packet+ iphdrlen+ sizeof(struct iphdr));

             printf("TCP Header\n");
             printf("Src port : %d\n", ntohs(tph->source));
             printf("Dest port : %d\n", ntohs(tph->dest));


             printf("--------------------------------------------\n");
             printf("\n");
           }


       }

   /* And close the session */
   }
   pcap_close(handle);
   return(0);
}
