from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

mac_to_port = {}

def install_flow(connection, in_port, dst, out_port):
    msg = of.ofp_flow_mod()
    msg.match.in_port = in_port
    msg.match.dl_dst = dst
    msg.actions.append(of.ofp_action_output(port=out_port))
    connection.send(msg)

def _handle_ConnectionUp(event):
    log.info("Switch %s connected", event.dpid)

def _handle_PacketIn(event):
    packet = event.parsed
    if not packet.parsed:
        return

    dpid = event.connection.dpid
    mac_to_port.setdefault(dpid, {})

    src = packet.src
    dst = packet.dst
    in_port = event.port

    log.info("Switch %s: %s -> %s", dpid, src, dst)

    # Learn MAC
    mac_to_port[dpid][src] = in_port

    # Decide output port
    if dst in mac_to_port[dpid]:
        out_port = mac_to_port[dpid][dst]
    else:
        out_port = of.OFPP_FLOOD

    # 🔥 FLOW ANALYZER LOGIC
    log.info("Installing flow: in_port=%s dst=%s out_port=%s",
             in_port, dst, out_port)

    # Install rule
    if out_port != of.OFPP_FLOOD:
        install_flow(event.connection, in_port, dst, out_port)

    # Send packet
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.in_port = in_port
    msg.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(msg)

def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)