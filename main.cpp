#include <pcap.h>
#include <stdio.h>

struct pac
{
    u_int dp;
    u_int sp;
    u_char sm[6] ;
    u_char dm[6] ;
    u_char si[4] ;
    u_char di[4] ;

} ;
struct pac a;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
void printsmac(const u_char* input){
    printf("smac:");

    for(int i=0;i<=5;i++)
    {

    a.sm[i]=input[i];
        printf("%02x ",a.sm[i] );
    }

    printf("\n");
}

void printdmac(const u_char* input){
    printf("dmac:");

    for(int i=6;i<=11;i++)
    {
a.dm[i-6]=input[i];
            printf("%02x ",a.dm[i-6] );
    }

    printf("\n");
}

bool check_ip(const u_char* input){

    if (input[12]==0x08 && input[13] == 0x00) //IPv4
        return true;
    else if (input[12]==0x86 && input[13] == 0xDD) //IPv6
        return true;

    return false;
}

bool check_tcp(const u_char* input){

    if (input[23]==0x06)
        return true;

    return false;
}

void printsip(const u_char* input){
    printf("sip:");
    for(int i=26;i<=29;i++)
    {
a.si[i-26]=input[i];
            printf("%3d ",a.si[i-26] );
    }
    printf("\n");
}

void printdip(const u_char* input){
    printf("dip:");
    for(int i=30;i<=33;i++)
    {

        a.di[i-30]=input[i];
            printf("%3d ",a.di[i-30] );
    }
    printf("\n");
}

void printsport(const u_char* input){
    printf("sport:");

    a.sp=((u_int)input[34] <<8 )+ (u_int)input[35];

            printf("%5u\n",a.sp );


}

void printdport(const u_char* input){
    printf("dport:");

    a.dp=((u_int)input[36] <<8 )+ (u_int)input[37];

           printf("%5u\n",a.dp );

}
void print_tdata(const u_char* input,struct pcap_pkthdr* header_input){

  if (input[54])
  {
      printf("tcpdata:");
            for(int i=0;i<10;i++)
               printf("%02x ",input[54+i]);r

            printf("\n");
          printf("size:%d\n",header_input->caplen-32);
}

}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    //for(int i= 0; i<=header->caplen ; i++)
    //printf("%x",packet[i]);

    printsmac(packet);
    printdmac(packet);
    if(check_ip(packet)==true) // eth -> ip check
    {
        printsip(packet);
        printdip(packet);
    }
      if(check_tcp(packet)==true) // ip -> tcp check
      {
        printsport(packet);
        printdport(packet);
        print_tdata(packet,header);
      }

  }

   printf("\n");
  pcap_close(handle);
  return 0;
}
