# Part 4 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

import pox.lib.packet as pkt

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}

# Convenience mappings of subnets to gateways
SUBNET2GATEWAY = {
    "10.0.1.0/24": IPAddr("10.0.1.1"),
    "10.0.2.0/24": IPAddr("10.0.2.1"),
    "10.0.3.0/24": IPAddr("10.0.3.1"),
    "10.0.4.0/24": IPAddr("10.0.4.1"),
    "172.16.10.0/24": IPAddr("172.16.10.1"),
}

# Mapping of ips to (ports, MACs) (Learn from incoming packets)
# Initialize gateway ips with unknown ports (these ports will be learned from ARP Request packets) and virtual MAC addresses
table = {
    IPAddr("10.0.1.1"): [None, EthAddr("00:00:00:00:01:01")],
    IPAddr("10.0.2.1"): [None, EthAddr("00:00:00:00:02:01")],
    IPAddr("10.0.3.1"): [None, EthAddr("00:00:00:00:03:01")],
    IPAddr("10.0.4.1"): [None, EthAddr("00:00:00:00:04:01")],
    IPAddr("172.16.10.1"): [None, EthAddr("00:00:00:00:05:01")],
}

# Mapping of ports to virtual MACs (Learn from incoming ARP Request packets)
port2VMAC = {}

class Part4Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    def flood(self):
        fm = of.ofp_flow_mod()
        fm.priority = 1 # a slightly higher priority than drop
        fm.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(fm)

    def drop(self):
        # drop other packets
        fm_drop = of.ofp_flow_mod()
        # ICMP
        fm_drop.priority = 0 # a low priority
        # flood all ports
        self.connection.send(fm_drop)

    def Set_up_rule(self, priority, dl_type, proto, src, dst, port_num):
        print("Set rule====", priority, dl_type, proto, src, dst, port_num)

        msg = of.ofp_flow_mod()

        if priority is not None:
            msg.priority = priority
            print("Priority", priority)

        if dl_type is not None:
            msg.match.dl_type = dl_type
            print("dl_type", dl_type)

        if proto is not None:
            msg.match.nw_proto = proto
            print("Proto", proto)

        if src is not None:
            msg.match.nw_src = IPS[src]
            print("nw_src", IPS[src])

        if dst is not None:
            msg.match.nw_dst = IPS[dst]
            print("nw_dst", IPS[dst])

        if port_num is not None:
            msg.actions.append(of.ofp_action_output(port=port_num))
            print("action port", port_num)

        self.connection.send(msg)
        print(msg)

    def s1_setup(self):
        #put switch 1 rules here
        self.flood()
        self.drop()

    def s2_setup(self):
        #put switch 2 rules here
        self.flood()
        self.drop()

    def s3_setup(self):
        #put switch 3 rules here
        self.flood()
        self.drop()

    def cores21_setup(self):
        # put core switch rules here
        # pass
        
        # block all ICMP traffic from untrusted host
        self.Set_up_rule(11,0x800,1,"hnotrust",None,None)
        
        # block all ipv4 traffic from untrusted host to serv1
        self.Set_up_rule(10,0x800,None,"hnotrust","serv1",None)

    def dcs31_setup(self):
        #put datacenter switch rules here
        self.flood()
        self.drop()

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )

        # ARP traffic handling
        if packet.type == packet.ARP_TYPE:
            
            # Learn the port and MAC of the incoming ARP packet
            if not packet.payload.protosrc in table:
                table[packet.payload.protosrc] = [event.port, packet.src]

            # ARP Requests handling
            if packet.payload.opcode == pkt.arp.REQUEST:
                # ARP Request with destination host's ip is not a gateway -> ignore
                if not packet.payload.protodst in table:
                    log.warning("Unknown destination host in ARP Request: " + str(packet.payload.protodst))
                    return

                # Learn the port of each gateway
                if not table.get(packet.payload.protodst)[0]:
                    # Map incoming port to the destination gateway
                    table[packet.payload.protodst][0] = event.port
                    
                    # Map the virtual MACs to the following ports
                    port2VMAC[event.port] = table.get(packet.payload.protodst)[1]

                # Send valid ARP Replies
                arp_reply = pkt.arp()
                arp_reply.hwsrc = table.get(packet.payload.protodst)[1] # Gateway's virtual MAC
                arp_reply.hwdst = packet.src
                arp_reply.opcode = pkt.arp.REPLY
                arp_reply.protosrc = packet.payload.protodst
                arp_reply.protodst = packet.payload.protosrc
                ether = pkt.ethernet()
                ether.type = pkt.ethernet.ARP_TYPE
                ether.dst = packet.src
                ether.src = table.get(packet.payload.protodst)[1]
                ether.payload = arp_reply
                    
                self.resend_packet(ether.pack(), event.port)

            # ARP Replies handling -> actually, we should ignore it because there are no ARP Replies generated in the network topology of part 4 :))
            elif packet.payload.opcode == pkt.arp.REPLY:
                log.warning("Abnormal incoming ARP Reply packet: " + packet.dump())
                return

            # ARP packet with unknown opcode -> ignore
            else:
                log.warning("Unknown ARP opcode: " + packet.payload.opcode + " from packet: " + packet.dump())
                return

        # IP traffic handling
        elif packet.type == packet.IP_TYPE:
            srcip = packet.payload.srcip
            dstip = packet.payload.dstip

            # Learn port and MAC address of the source host
            # Although processing ARP is sufficient, this is for sure :))
            if not srcip in table:
                table[srcip] = [event.port, packet.src]

            # Only proceeding the incoming packet if the destination host's port and MAC are learned
            if dstip in table:
                # L2 header updating and forwarding
                # Create a flow mod indicating that packet sent to the destination host's IP must have header updated and forwarded to the right port
                msg = of.ofp_flow_mod()
                msg.match.dl_type = packet.IP_TYPE
                msg.match.nw_dst = dstip
                msg.actions.append(of.ofp_action_dl_addr.set_src(port2VMAC.get(table.get(dstip)[0])))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(table.get(dstip)[1]))
                msg.actions.append(of.ofp_action_output(port = table.get(dstip)[0]))
                msg.priority = 5

                self.connection.send(msg)
                self.resend_packet(packet_in.data, of.OFPP_TABLE)

            #  IP traffic whose destination port and MAC are unknown -> ignore
            else:
                log.warning("IP packet had unknown destination host properties (port, MAC): " + packet.dump())
        # Another incoming traffic -> ignore
        else:
            log.warning("Another type of incoming packet: " + packet.dump())

def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
