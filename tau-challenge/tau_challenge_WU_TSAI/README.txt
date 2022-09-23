Creators: Chen-Yen WU, Richard Bing-Shiun TSAI

Templates taken from the moodle (delta challenge). Tested on the VM associated to sigmachallenge.

Idea:
1. Once we see the SYN, SYN-ACK packets between the server and the client, we send a RST-ACK packet to the client to make the client believe that the connection has been reset.
2. Then we pretend to be the client and interact with the server.

Implementation:
-All the comments are in the code.

Instruction/Demonstration:
1. Launch the tcp_hijack program. It automatically listens to the vboxnet0 and lo0 interface with filter = "host 192.168.56.101 && tcp".
2. Open another terminal to act as a client. Use this instruction to connect to the VM server: telnet 192.168.56.101 2000
3. The tcp_hijack program will hijack this connection and interact with the server.
4. Send anything you want to the server via the tcp_hijack program, the server will gently reply to you.

Remarks:
1. After disconnection with the server, if the client sees incoming packets, he will send RST packets back to the server, thus shutting down the connection. To deal with this, we've tried a lot of methods without succeeding. Finally, we go into the real server VM, and type in the command line "iptables -I INPUT -p tcp --tcp-flags ALL RST -j DROP". This commands construct a "firewall" so that the server doesn't read the RST packets from the real client.
2. In the tcp header, the part "option" takes 12 byte (called size_TcpOption) so to localize the payload, we set up char * pointer_data = iphdr + sizeof(struct iphdr) + sizeof(struct tcphdr) + size_tcpOption
