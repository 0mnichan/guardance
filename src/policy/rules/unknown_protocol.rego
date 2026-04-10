# unknown_protocol.rego — detect protocols not in the OT allowlist.
#
# Input schema:
#
#   {
#     "edges": [
#       {
#         "src_ip":        "192.168.1.10",
#         "dst_ip":        "10.0.0.1",
#         "protocol":      "http",
#         "port":          80,
#         "function_code": "flow",
#         "packet_count":  5,
#         "first_seen":    1700000500.0
#       }, ...
#     ],
#     "allowed": ["modbus", "dnp3", "s7comm", "tcp", "udp"]
#   }

package guardance.unknown_protocol

import future.keywords.if
import future.keywords.in

default violations := []

violations[result] if {
    edge := input.edges[_]
    not edge.protocol in input.allowed

    result := {
        "src_ip":        edge.src_ip,
        "dst_ip":        edge.dst_ip,
        "protocol":      edge.protocol,
        "port":          edge.port,
        "function_code": edge.function_code,
        "packet_count":  edge.packet_count,
        "first_seen":    edge.first_seen,
    }
}
