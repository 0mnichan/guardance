# cross_zone.rego — detect communication across non-adjacent Purdue levels.
#
# Input schema (provided by PolicyEngine.evaluate):
#
#   {
#     "edges": [
#       {
#         "src_ip":       "192.168.1.10",
#         "dst_ip":       "10.0.0.1",
#         "protocol":     "modbus",
#         "port":         502,
#         "function_code": "READ_HOLDING_REGISTERS",
#         "packet_count": 120
#       }, ...
#     ],
#     "devices": {
#       "192.168.1.10": {
#         "ip": "192.168.1.10",
#         "zone": {"name": "Field", "purdue_level": 1}
#       }, ...
#     }
#   }

package guardance.cross_zone

import future.keywords.if
import future.keywords.in

default violations := []

violations[result] if {
    edge := input.edges[_]

    src := input.devices[edge.src_ip]
    dst := input.devices[edge.dst_ip]

    src.zone != null
    dst.zone != null

    level_diff := abs(src.zone.purdue_level - dst.zone.purdue_level)
    level_diff > 1

    result := {
        "src_ip":       edge.src_ip,
        "dst_ip":       edge.dst_ip,
        "src_zone":     src.zone.name,
        "dst_zone":     dst.zone.name,
        "src_level":    src.zone.purdue_level,
        "dst_level":    dst.zone.purdue_level,
        "level_diff":   level_diff,
        "protocol":     edge.protocol,
        "port":         edge.port,
        "packet_count": edge.packet_count,
    }
}
