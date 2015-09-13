from __future__ import print_function

from getpass import getpass

from os import popen

from keyring import get_password, set_password

import re

from libcloud.dns.providers import get_driver
from libcloud.common.types import InvalidCredsError

def get_driver_and_zones(driver_name, account_name):
    """
    Get the DNS driver, authenticate, and get some zones.
    """
    secret_site = "libcloud/" + driver_name
    cls = get_driver(driver_name)
    pw = get_password(secret_site, account_name)

    if not pw:
        pw = getpass("Password:")

    while True:
        try:
            dns = cls(account_name, pw)
            zones = dns.list_zones()
        except InvalidCredsError:
            pw = getpass("Password:")
        else:
            set_password(secret_site, account_name, pw)
            return dns, zones


import attr
@attr.s
class IPv6Address(object):
    """
    One IPv6 address.
    """
    address = attr.ib()
    valid_lifetime = attr.ib()
    preferred_lifetime = attr.ib()

    @classmethod
    def from_ip_output_line(cls, line):
        """
        Initialize an IPv6Address from the output of 'ip -o'.

        example output line (backslash literally included) with accompanying
        indices::

            5: br0 inet6 ffff::ffff/64 scope global mngtmpaddr dynamic \
               valid_lft 6971sec preferred_lft 1571sec
            0  1   2     3             4     5      6          7       8
               9         10      11            12
        """
        fields = line.split()
        addr_and_mask = fields[3]
        def seconds_int(value):
            return int(value.rstrip("sec"))
        return cls(address=addr_and_mask.split("/")[0],
                   valid_lifetime=seconds_int(fields[10]),
                   preferred_lifetime=seconds_int(fields[12]))

    @classmethod
    def all_global_addresses(cls):
        """
        Yield all globally-scoped IPv6 addresses on this computer in order.
        """
        with popen("ip -o -d -6 addr show primary scope global br0") as f:
            return [cls.from_ip_output_line(line) for line in f]

    @classmethod
    def one_global_address(cls):
        """
        Get the longest-lived globally addressable IPv6 address.
        """
        addrs = cls.all_global_addresses()
        # longest preferred lifetime first
        addrs.sort(key=lambda x: x.preferred_lifetime)
        addrs.reverse()

        # fe80, fc00::/7, ff0X::n, fec0::/10... all start with 'f'
        addrs = [addr for addr in addrs if not addr.address.startswith('f')]
        return addrs[0]


def update_one_record(dns, zones, record_name, record_type, data):
    """
    Update a DNS record to point at a specific value, creating it if necessary,
    deleting any other records of other types pointing at the same DNS name if
    necessary.

    @param dns: The DNS provider.

    @param zones: The list of zone objects from the DNS provider.

    @param record_name: The fully qualified domain name to update.

    @param record_type: The type of the record ("A" or "AAAA" probably).

    @param data: The data to update the record with (the string formated IP
        address).
    """
    sub_domain, top_level_domain = (
        re.match("(?:(.*)\\.|)(.*\\..*)", record_name).groups()
    )

    for zone in zones:
        if zone.domain == top_level_domain:
            target_zone = zone

    for record in dns.iterate_records(target_zone):
        if record.name == sub_domain:
            if record.type != record_type:
                dns.delete_record(record=record)
            else:
                dns.update_record(record=record, name=sub_domain,
                                  type=record_type, data=data,
                                  extra=dict(ttl=300))
                break
    else:
        target_zone.create_record(name=sub_domain, type=record_type, data=data,
                                  extra=dict(ttl=300))

def dynamic_ipv6_dns_update(driver_name, account_name, hostname):
    """
    For the given DNS driver and account name, update the given hostname to
    point at a single IPv6 address, this machine's current global address.
    """
    driver, zones = get_driver_and_zones(driver_name, account_name)
    update_one_record(driver, zones, hostname, "AAAA",
                      IPv6Address.one_global_address().address)

if __name__ == '__main__':
    import sys
    dynamic_ipv6_dns_update(sys.argv[1], sys.argv[2], sys.argv[3])
