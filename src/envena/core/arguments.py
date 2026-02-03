import ipaddress
import logging
from math import inf
from typing import Annotated, Union

import netaddr
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator
from scapy.all import conf, get_if_addr, get_if_hwaddr, get_if_list

from src.envena.core.logger import ROOT_LOGGER_NAME
from src.envena.utils.parsers import parse_submask
from src.envena.utils.validators import get_validated_eth, get_validated_ip

MacAddress = Annotated[netaddr.EUI, BeforeValidator(get_validated_eth)]
IpAddress = Annotated[
    Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    BeforeValidator(get_validated_ip),
]


class Arguments(BaseModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True, validate_assignment=True, extra="forbid"
    )

    ######
    # L7 #
    ######
    dns_server: IpAddress = Field(default=ipaddress.ip_address("8.8.8.8"))
    xid: int = 0

    ######
    # L4 #
    ######
    port_src: int = Field(default=0, ge=0, le=65535)
    port_dst: int = Field(default=0, ge=0, le=65535)

    ######
    # L3 #
    ######
    sub_ip: IpAddress = Field(default=ipaddress.ip_address("0.0.0.0"))
    sub_mask: str = "255.255.255.0"
    ip_dst: IpAddress = Field(default=ipaddress.ip_address("0.0.0.0"))

    ip_src: IpAddress = Field(
        default_factory=lambda: ipaddress.ip_address(get_if_addr(conf.iface))
    )

    ######
    # L2 #
    ######
    iface: str = Field(default_factory=lambda: str(conf.iface))

    eth_src: MacAddress = Field(
        default_factory=lambda: netaddr.EUI(get_if_hwaddr(conf.iface).replace(":", "-"))
    )
    eth_dst: MacAddress = Field(default=netaddr.EUI("00-00-00-00-00-00"))
    hw_src: MacAddress = Field(
        default_factory=lambda: netaddr.EUI(get_if_hwaddr(conf.iface).replace(":", "-"))
    )
    hw_dst: MacAddress = Field(default=netaddr.EUI("00-00-00-00-00-00"))
    bssid: MacAddress = Field(default=netaddr.EUI("00-00-00-00-00-00"))
    ssid: str = Field(default="", max_length=32)

    ###############
    # App / Other #
    ###############
    count: Annotated[Union[int, float], Field(ge=0)] = 1
    timeout: float = Field(default=0.0, ge=0)
    input: str = ""

    logger: logging.Logger = Field(
        default_factory=lambda: logging.getLogger(f"{ROOT_LOGGER_NAME}.Arguments"),
        exclude=True,
    )

    ##############
    # Validators #
    ##############
    @field_validator("iface")
    @classmethod
    def check_iface_exists(cls, v: str) -> str:
        if v not in get_if_list():
            raise ValueError(f"Interface '{v}' not found in system")
        return v

    @field_validator("sub_mask")
    @classmethod
    def validate_mask(cls, v: str) -> str:
        mask = parse_submask(v)
        if not mask:
            raise ValueError(f"Invalid sub_mask: {v}")
        return str(mask)

    @field_validator("count")
    @classmethod
    def check_count(cls, v):
        if not (isinstance(v, int) or v == inf):
            raise TypeError("Count must be a not-negative integer or math.inf")
        return v


public_args = Arguments()
