from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    self.connection.send(msg)
    #add switch rules here
    
    ##Rule for accepting all ICMP traffic
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    match.nw_src = None #wildcard for all addresses
    match.nw_dst = None #wildcard for all addresses
    match.dl_type = 0x800
    match.nw_proto = pkt.ipv4.ICMP_PROTOCOL #pkt.ipv4.ICMP_PROTOCOL
    msg.match = match
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    #msg.actions.append(of.OFPP_FLOOD)
    self.connection.send(msg)
    
    ##Rules for accepting all ARP traffic
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    match.nw_src = None #wildcard for all addresses
    match.nw_dst = None #wildcard for all addresses
    match.dl_type = 0x806
    match.nw_proto = None 
    #by setting dl_type to ARP then we can just set nw_proto to wildcard 
    msg.match = match
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)

    ##Rule for rejecting all other traffic
    msg = of.ofp_flow_mod()
    match = of.ofp_match() 
    #leaving all fields undefined wildcards them and default 
    msg.match = match 
    #msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
    self.connection.send(msg)
    

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet :" + str(packet.dump()))

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
