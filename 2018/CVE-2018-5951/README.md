CVE-2018-5951: MikroTik RouterOS Denial of Service Vulnerability
---

### Vulnerability Summary
A vulnerability in MikroTik RouterOS allows an unauthenticated remote attacker to force a router to reboot. This is done by sending a packet of the size of 1 byte to RouterOS's IPv6 address using IP proto 97. All versions of RouterOS with EoIPv6 support are likely vulnerable to this attack. This attack required target system to have IPv6 enabled and had at least one tunnel interface present.

### Attack Vector
- IPv6 is enabled on the target system.
- No IPv6 filter rule blocking `INPUT` of IP proto 97.
- At least one tunnel interface present in the target system. (tunnel type does not matter) 

### Vulnerability Overview
EoIPv6 (Ethernet over IPv6) are MikroTik RouterOS's Layer 2 tunneling protocol. The EoIPv6 protocol encapsulates Ethernet frames in a modified EtherIP (IP proto 97) packets.

MikroTik's implement of EoIPv6 uses 12 reserved bits of EtherIP to store tunnel ID. MikroTik also swapped the first 4 bits and the second 4 bits of the EtherIP header. 

To retrieve tunnel ID and validate the packet, RouterOS will swap bits as described above on packets received on proto 97. The process happens as long as there are tunnel interfaces present in the system (even if it is disabled). RouterOS does not check the payload size during the process. So a one byte packet on proto 97 will break it (since the rest of bits required to build the tunnel ID are missing). 

### Proof of Concept
On RouterOS, add an IPv6: 

```
/ipv6 address add interface=ether1 address=fd00::1/64 advertise=no
```

And a tunnel (any type):

```
/interface ipip add remote-address=127.0.0.1
```

Run the exploit (`exploit.c` in repo):

```
./exploit fd00::1
```

RouterOS will reboot itself in a few seconds after the exploit. The following logs can be seen after reboot:

```
jan/20/2018 10:28:36 system,error,critical router was rebooted without proper shutdown
```

### Tested Versions
RouterOS `6.39.3` (Bugfix only), `6.41` (Current) and `6.42rc11` (Release candidate) are tested, and all of them are vulnerable to this attack at the time of writing. This vulnerability is likely to present in the older versions of RouterOS with EoIPv6 support as well.

### Workaround
See [this thread](https://forum.mikrotik.com/viewtopic.php?t=130557) on MikroTik forum.
