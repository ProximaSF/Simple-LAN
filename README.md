# LAN (Local Area Network)

Project Description (2 layers):

Connect two laptop via a Ethernet connection (static) and write a simple `Scapy` Python script to capture packet transfer (ping) from one system to another. Also learn how to share document on Windows.

## Processes


1. Connect two laptop via a Ethernet cable using an adaptor

2. Turn off Firewall ([specifically Public settings](#firewall))

3. In connecting setting, use static/manuel setup for IPv4

   ``` 
   Laptop 1:
   IPv4 Address: 10.0.0.1
   Subnet Mask: 255.255.255.0
   
   Laptop 2:
   IPv4 Address: 10.0.0.2
   Subnet Mask: 255.255.255.0
   ```

   Check connection in terminal:

   ```powershell
   # Laptop 1
   ping 10.0.0.0.2
   ```

   ```powershell
   # Laptop 2
   ping 10.0.0.0.1
   ```

4. File Share (Windows):

   - Go `Advanced Sharing` in settings

     - Under `Public Network` select all the boxes
     - Under `all networks` select `public folder sharing`
     - Repeat for other computer

   - Locate a folder/file to share (laptop 1)

     - Right click and select `properties`
     - Click `sharing` option and click on `share...`
     - In the drop down, click on `everyone` and add
     - Change permission as needed

   - On laptop 2

     - Open file explorer and in the search, type the network path from laptop 1:

       ```
       \\LAPTOP1\folder_name
       ```

     - If password required, enter laptop login info (can turn off password requirement in `Advanced sharing`)

   - Copy and past the share folder to transfer



## Packet Sniff (Network Frame)

A frame/packet is a data transmission at the link layer (Layer 2) of computer network that have a specific structure.

- It includes address information, error detection, and payload data

- Frame travels across the physical network media (Ethernet or Wifi)

  

### Code Meanings:

1. `def check_interfaces()`
   - Find all interface being connected to the laptop and display their MAC and IP address
2. `my_frame = Ether() / IP()`
   - Creates a simple network transmission packet with two layers: ethernet layer (layer 2) and IP layer (layer 3)
   - The `/` operator is used to stack protocol layers together when constructing network packets

3. `packets = sniff(count=2, iface=interface)`
   - It captures 2 network packets that happens to flow from laptop 1 to laptop 2 or another device
   - `iface` filter out which interface/device want to capture packets from
   - `packets2 = sniff(count=2, filter='icmp', iface=interface)`
     - This is  the same but only grabbing packets that have a protocol of <u>ICMP</u> (internet control match protocol)
4. `summary = [p.summary() for p in packets]`
   - Create a list of summary for each packet in `packets`
   - Typically show protocol types, source/destination addresses, and others. 
5. `def packet_data(packet_order, layer, value=None)`
   - Return the extracted data from the packet based which packet, the packet layer type (Ip, ether, tcp, etc) and the value of the layer based on a field it has.



### Result Meaning

1. `Ether / 127.0.0.1 > 127.0.0.1 ip`

   - Basic Ethernet/IP packet with the localhost IP address (127.0.0.1)
2. `<Sniffed: TCP:0 UDP:0 ICMP:2 Other:0>`

   - Captured 2 ICMP packets (no TCP, UDP or other protocols).
3. `Ether / IP / ICMP 10.0.0.2 > 10.0.0.1 echo-request 0 / Raw`
   `Ether / IP / ICMP 10.0.0.1 > 10.0.0.2 echo-reply 0 / Raw`

   - The summary shows captured a <u>ping</u> request and response

     - **First packet:** echo-request ping from 10.0.0.2 to 10.0.0.1
     - **Second packet:** echo-reply from 10.0.0.1 back to 10.0.0.2
4. `[<Ether  dst=c8:a3:62:bd:d7:5b src=c8:a3:62:be:ce:4e type=IPv4 |<IP  version=4 ihl=5 ...]`
   - MAC addresses (in the Ethernet layer)
   - IP information (version 4, TTL of 128, etc.)
   - ICMP details (request/reply types, checksums)
   - Raw data payload ("abcdefghijklmnopqrstuvwabcdefghi")



## Firewall

The purpose is to inspect and filter traffic

- When establishing a connection via LAN through a ethernet cable, windows will treat the connection as public connection.
- The firewall layer is above layer 2 so it can block traffic/communication of the lower layers.



## Side Info

1. **OSI (open system interconnection)** network model layers (First 4)
   - Layer 1 (physcial):
     - Physical hardware (cables, connectors, PC, etc)
     - Transmission methods
     - Signal types (electrical, light, etc
     - Physical topologies (bus, star, etc)
   - Layer 2 (data link):
     - Ethernet, MAC address, switches, etc
     - Some protocols (PPP, HDLC, wi-fi, bluetooth)
   - Layer 3 (network layer):
     - IP (Internet Protocol), routing, etc
     - Various protocol (ICPM (ping),  OSPF, BGP, RIP, etc)
   - Layer 4 (transport layer):
     - Main protocol (<u>TCP (transmission control protocol)</u> and <u>UDP (user datagram protocol)</u>)
     - Handles: Port numbers, connection management, segmentation
     - Error recovery, flow control

2. MAC (Media Access Control) addresses are unique identifiers assigned to network interfaces

   - Permanently assigned to a device during manufacturing
   - Has a 48-bit (6-byte) hardware address.
   - Usually displayed as six pairs of hexadecimal digits (i.e `e8:fb:1c:14:eb:49`)
   - Helps identify which physical devices are communicating

3. IP addresses are numerical labels assigned to devices on a network

   - IPv4 has a 32-bit written in four decimal numbers (i.e `129.342.1.234`)
   - Address be assigned dynamically (DHCP) or statically configured (manual)

4. Raw data in packet summaries refers to the actual payload data.

   - The actual content being transmitted

   - Often encrypted for secure protocols like HTTPS

   - The data can be valuable as it could be decoded to more inspection# Simple-LAN