from .upnp import Device
from .util import _getLogger
import socket
import re
from datetime import datetime, timedelta
import select
import ifaddr
from urllib.parse import urlparse

RESPONSE_REGEX = re.compile(r'\n(.*?)\: *(.*)\r')


def create_ssdp_request(ssdp_st, ssdp_mx, ssdp_ip, ssdp_port):
    """Return request bytes for given st and mx."""
    return "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'ST: {}'.format(ssdp_st),
        'MX: {:d}'.format(ssdp_mx),
        'MAN: "ssdp:discover"',
        'HOST: {}:{}'.format(ssdp_ip, ssdp_port),
        '', '']).encode('utf-8')


class SSDPResponse(object):
    def __init__(self, response):
        self.response = response
        self.values = {
            attr.strip().lower(): value.strip()
            for attr, value
            in RESPONSE_REGEX.findall(response)
        }

    def __repr__(self):
        return "<SSDPResponse from '{location}'>".format(
            location=urlparse(self.location).netloc
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


def scan(timeout=5, ssdp_ip="239.255.255.250", ssdp_port=1900, ssdp_st='ssdp:all', addr=None, ttl=1):
    # TODO: Allow Unicast SSDP Discover scan (Maybe do a scan_unicast and scan_multicast function)
    # TODO: Allow Setting of 'SEARCHPORT.UPNP.ORG' header to redirect ssdp responses
    # TODO: Comment this crazy code
    if timeout < 2:
        timeout = 2
    ssdp_mx = timeout-1
    ssdp_responses = []
    sockets = []
    ssdp_request = create_ssdp_request(
        ssdp_st=ssdp_st,
        ssdp_mx=ssdp_mx,
        ssdp_ip=ssdp_ip,
        ssdp_port=ssdp_port
    )
    stop_wait = datetime.now() + timedelta(seconds=timeout)

    if addr is None:
        addr = get_all_address()
    elif isinstance(addr, str):
        addr = [addr]

    for ip in addr:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # TODO: Check if unicast or multicast an set ttl accordingly
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.bind((ip, 0))
            sockets.append(sock)
        except socket.error:
            pass

    for sock in sockets:
        try:
            sock.sendto(ssdp_request, (ssdp_ip, ssdp_port))
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
                # location is not already the same as of another response
                ssdp_resp = SSDPResponse(response)
                if ssdp_resp.location not in [resp.location for resp in ssdp_responses]:
                    ssdp_responses.append(ssdp_resp)

    finally:
        for s in sockets:
            s.close()

    return ssdp_responses


def get_all_address():
    '''
    Getting ipv4 addresses of local interfaces
    '''
    return list(set(
        addr.ip for iface in ifaddr.get_adapters() for addr in iface.ips if addr.is_IPv4
        )
    )


def discover(timeout=5):
    """
    Convenience method to discover UPnP devices on the network. Returns a
    list of `upnp.Device` instances. Any invalid servers are silently
    ignored.
    """
    ssdp_responses = scan(timeout=timeout)

    devices = []
    for resp in ssdp_responses:
        try:
            dev = Device.from_ssdp_response(ssdp_response=resp)
            devices.append(dev)
        except Exception as err:
            log = _getLogger("ssdp")
            log.error('Error \'%s\' for %s', err, resp.location)

    return devices
