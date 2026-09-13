"""FortiOS BGP summary adapter."""

from types import MappingProxyType

from ...cisco.ios.bgp import parse_status

COMMANDS = MappingProxyType({"summary": "get router info bgp summary"})
MOCK_OUTPUTS = MappingProxyType({
    "summary": """BGP router identifier 10.0.0.1, local AS number 65100
Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4 65200      90      92      8   0    0 02:14:09           12""",
})
