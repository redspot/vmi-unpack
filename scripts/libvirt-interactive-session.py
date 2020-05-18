import libvirt
from vmcloak.agent import Agent
import xml.etree.ElementTree as ET
from unittest.mock import MagicMock
logger = MagicMock()
LIBVIRT_CONN_SINGLETON = None

def ping_loop(_agent):
    while True:
        try:
            _agent.ping()
            break
        except:
            pass


def connect_to_libvirt():
    global LIBVIRT_CONN_SINGLETON
    if not isinstance(LIBVIRT_CONN_SINGLETON, libvirt.virConnect):
        LIBVIRT_CONN_SINGLETON = libvirt.open(None)
        logger.debug("connected to libvirt")
    return LIBVIRT_CONN_SINGLETON


def get_domain(_dom_name):
    global LIBVIRT_CONN_SINGLETON
    return LIBVIRT_CONN_SINGLETON.lookupByName(_dom_name)


def dumpxml(_dom):
    return ET.fromstring(_dom.XMLDesc())


def _get_mac_addrs(_xml):
    mac_addr = None
    egress_mac_addr = None
    iface_xpath = ".//interface[@type='network']"
    agent_network = 'hostonly'
    egress_network = 'default'
    ifname_xpath = "./source[@network='{}']"
    for node in _xml.findall(iface_xpath):
        if mac_addr is None:
            if node.find(ifname_xpath.format(agent_network)) is not None:
                mac_addr = node.find("mac").attrib['address']
        if egress_mac_addr is None:
            if node.find(ifname_xpath.format(egress_network)) is not None:
                egress_mac_addr = node.find("mac").attrib['address']
    logger.debug(f" mac_addr={mac_addr}"
                 f" egress_mac_addr={egress_mac_addr}")
    return (mac_addr, egress_mac_addr)

def get_network_info(_dom, _xml):
    guest_ip = None
    egress_nic = None
    mac_addr, egress_mac_addr = _get_mac_addrs(_xml)
    ifaces = _dom.interfaceAddresses(
            libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
    for key, val in ifaces.items():
        if val['addrs'] and val['hwaddr'] == mac_addr:
            guest_ip = val['addrs'][0]['addr']
        if val['addrs'] and val['hwaddr'] == egress_mac_addr:
            egress_nic = key
    logger.debug(f"domain={_dom.name()}"
                 f" guest_ip={guest_ip}"
                 f" egress_nic={egress_nic}")
    return (guest_ip, egress_nic)

notes = """examples:
connect_to_libvirt()
dom = get_domain('win7-borg')
dom_xml = dumpxml(dom)
dom.isAlive()
guest_ip, _ = get_network_info(dom, dom_xml)
a = Agent(guest_ip)
a.execute('c:/users/customer/music/hello_mpress.exe', _async=True)
a.upload('c:/users/customer/music/sample_02b5.exe',
open('/home/wmartin45/borg-out/6samples/'
'02b5be3363e61f6b77919d19de88960021bc8795c2e56ba785c3e8498d86dfba',
'rb').read()
)
"""
print(notes)

