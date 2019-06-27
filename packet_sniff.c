#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>


/* compile (example) with: "gcc -g -o packet_sniff packet_sniff.c -lpcap"
 * if not root: run with "sudo ./packet_sniff"
 * */

int main (int argc, char** argv){
  char errbuff[PCAP_ERRBUF_SIZE]; /*or [PCAP_ERRBUF_SIZE]*/
  pcap_if_t * alldevsp; /*pointer to list containing devices suitable for packet capture*/
  char * device_name; /*name of device to open*/
  pcap_t * device_handler; /*interface handler of device*/
  char filter[]="tcp portrange 60-7000"; /*filter that will be compiled & set*/
  struct bpf_program filter_compiled; /*compiled filter*/
  bpf_u_int32 mask; /*netmask / subnet of device involved in sniffing
                     *netmask divides IP into subnets and host addresses 
                     */
  bpf_u_int32 net; /*the device IP*/
  struct pcap_pkthdr header; /*header containing info about packet */
  const u_char *packet;/*the actual packet captured*/

  /*1. look up device:
   * can be done with ...
   *
   *... pcap_lookupdev: returns the first device that can be sniffed on 
   *... pcap_findalldevs: returns a list containing all possible devices that can be sniffed on
   * */

  /*find all devices available for packet capture, and print out*/
  if(pcap_findalldevs(&alldevsp, errbuff) == PCAP_ERROR){
      fprintf(stderr, "Error @ Line: %d: %s\n", __LINE__, pcap_geterr(device_handler));
      exit(1);
  }

  pcap_if_t * devptr;

  printf("-------------------------------------\n");
  printf("Devices available for capture:\n\n");
  for(devptr=alldevsp; devptr!=NULL; devptr=devptr->next){
      printf("Device Name: %s\t", devptr->name);

      if(strcmp(devptr->name, "wlp2s0")==0) device_name = devptr->name;
      if(devptr->description != NULL){
          printf("Description: %s\n", devptr->description);
      }else printf("\n");

  }
  printf("\n");

  /*use look up dev to find first available device for packet capture*/
 /* if((device_name = pcap_lookupdev(errbuff)) == NULL){
      fprintf(stderr, "Couldn't find default device:  %s\n", errbuff);
      exit(1);
  }
*/

  /*find subnet & IP of device in order to apply filters later*/
  if(pcap_lookupnet(device_name, &net, &mask, errbuff) == -1){
      fprintf(stderr, "Error @ line %d: Couldn't obtain netmask for device %s\n", __LINE__, errbuff);
      exit(1);
  }

  printf("Now using device: %s\n", device_name);
  printf("IP: %u\t Netmask: %u\n\n", net, mask);



  /*open one of the devices*/
  if((device_handler = pcap_open_live(device_name, 65535, 1, 1000, errbuff)) == NULL){
      fprintf(stderr, "Error @ line %d: Couldn't find device %s\n", __LINE__, errbuff);
      exit(1);
  }


  /*compile & set a filter*/
   if(pcap_compile(device_handler, &filter_compiled, filter, 0, net) == PCAP_ERROR){
      fprintf(stderr, "Error @ Line %d: Filter compile failed: %s\n", __LINE__, pcap_geterr(device_handler));
      exit(1);
  }

  if(pcap_setfilter(device_handler, &filter_compiled) == -1){
      fprintf(stderr, "Error @ Line: %d: Filter set failed: %s\n", __LINE__, pcap_geterr(device_handler));
      exit(1);
  }


  printf("Now capturing packet...\n");
  /*catch packet*/
  packet = pcap_next(device_handler, &header);
  printf("Packet length: [%d]\n", header.len);

  /*close handle*/
  pcap_close(device_handler);


  //free list of all devs
  pcap_freealldevs(alldevsp);
  return 0;
}
