#include <stdio.h>
#include <linux/bpf.h>
#include <net/ethernet.h>
#include <linux/if_vlan.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <net/if.h>

int main()
{
   unsigned int indexofeth0 = 0;
   unsigned int indexofeth1 = 0;
   
   indexofeth0 = if_nametoindex("ens33");
   indexofeth1 = if_nametoindex("ens35");

   printf("%d, %d", indexofeth0, indexofeth1);
   return 1;
}

