from .upnp import Device
from .util import _getLogger
import socket
import re
from datetime import datetime, timedelta
import select
import ifaddr
import re

DISCOVER_TIMEOUT = 2
SSDP_TARGET = ("239.255.255.250", 1900)
SSDP_MX = DISCOVER_TIMEOUT
ST_ALL = "ssdp:all"
ST_ROOTDEVICE = "upnp:rootdevice"
RESPONSE_REGEX = re.compile(r'\n(.*?)\: *(.*)\r')


class SSDPResponse(object):
    def __init__(self, response):
        self.response = response
        self.values = {
            attr.lower(): value
            for attr, value
            in RESPONSE_REGEX.findall(response)
        }

    def __repr__(self):
        # TODO: Only show ip from location
        # do that with urlparse
        return "<SSDPResponse from '{location}'>".format(
            location=self.location
        )
    
    def __str__(self):
        return self.response

    @property
    def cachecontrol(self):
        return self.values.get('cache-control', '')

    @property
    def date(self):
        return self.values.get('date', '')

    @property
    def ext(self):
        return self.values.get('ext', '')

    @property
    def location(self):
        return self.values.get('location', '')

    @property
    def opt(self):
        return self.values.get('opt', '')

    @property
    def nls(self):
        return self.values.get('01-nls', '')

    @property
    def server(self):
        return self.values.get('server', '')

    @property
    def xuseragent(self):
        return self.values.get('x-user-agent', '')

    @property
    def st(self):
        return self.values.get('st', '')

    @property
    def usn(self):
        return self.values.get('usn', '')


def ssdp_request(ssdp_st, ssdp_mx=SSDP_MX):
    """Return request bytes for given st and mx."""
    return "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'ST: {}'.format(ssdp_st),
        'MX: {:d}'.format(ssdp_mx),
        'MAN: "ssdp:discover"',
        'HOST: {}:{}'.format(*SSDP_TARGET),
        '', '']).encode('utf-8')


def scan(timeout=5):
    # TODO: Comment this crazy code
    ssdp_responses = []
    sockets = []
    ssdp_requests = [ssdp_request(ST_ALL), ssdp_request(ST_ROOTDEVICE)]
    stop_wait = datetime.now() + timedelta(seconds=timeout)

    for addr in get_all_address():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                            SSDP_MX)
            sock.bind((addr, 0))
            sockets.append(sock)
        except socket.error:
            pass

    for sock in [s for s in sockets]:
        try:
            for req in ssdp_requests:
                sock.sendto(req, SSDP_TARGET)
            sock.setblocking(False)
        except socket.error:
            sockets.remove(sock)
            sock.close()
    try:
        while sockets:
            time_diff = stop_wait - datetime.now()
            seconds_left = time_diff.total_seconds()
            if seconds_left <= 0:
                break

            ready = select.select(sockets, [], [], seconds_left)[0]

            for sock in ready:
                try:
                    data, address = sock.recvfrom(1024)
                    response = data.decode("utf-8")
                except UnicodeDecodeError:
                    _getLogger(__name__).debug(
                        'Ignoring invalid unicode response from %s', address)
                    continue
                except socket.error:
                    _getLogger(__name__).exception(
                        "Socket error while discovering SSDP devices")
                    sockets.remove(sock)
                    sock.close()
                    continue
                
                # Create a SSDPResponse object and append to list if
                # location is not already the same of another response
                resp = SSDPResponse(response)
                if resp.location not in [x.location for x in ssdp_responses]:
                    ssdp_responses.append(resp)

    finally:
        for s in sockets:
            s.close()

    return ssdp_responses


def get_all_address():
    '''
    Getting ipv4 addresses of local interfaces
    '''
    return list(set(addr.ip for iface in ifaddr.get_adapters() for addr in iface.ips if addr.is_IPv4))


def discover(timeout=5):
    """
    Convenience method to discover UPnP devices on the network. Returns a
    list of `upnp.Device` instances. Any invalid servers are silently
    ignored.
    """
    ssdp_responses = scan(timeout)

    devices = []
    for resp in ssdp_responses:
        try:
            dev = Device.from_ssdp_response(resp)
            devices.append(dev)
        except Exception as err:
            log = _getLogger("ssdp")
            log.error('Error \'%s\' for %s', exc, entry)

    return devices
