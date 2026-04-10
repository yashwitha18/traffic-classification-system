from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0
}

def _handle_PacketIn(event):
    packet = event.parsed

    ip_packet = packet.find('ipv4')
    if not ip_packet:
        return

    protocol = None

    if ip_packet.find('tcp'):
        protocol = "TCP"
    elif ip_packet.find('udp'):
        protocol = "UDP"
    elif ip_packet.find('icmp'):
        protocol = "ICMP"

    if protocol:
        stats[protocol] += 1

    total = sum(stats.values())

    print("\n===== Traffic Statistics =====")
    for proto, count in stats.items():
        percent = (count / total) * 100 if total else 0
        print(f"{proto}: {count} packets ({percent:.2f}%)")

    # install flow rule
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    msg.data = event.ofp   # VERY IMPORTANT
    event.connection.send(msg)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Traffic Classification Controller Started")












