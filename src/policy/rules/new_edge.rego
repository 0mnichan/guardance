# new_edge.rego — detect communication edges first seen after the baseline period.
#
# Input schema:
#
#   {
#     "edges": [
#       {
#         "src_ip":        "192.168.1.10",
#         "dst_ip":        "10.0.0.1",
#         "protocol":      "modbus",
#         "port":          502,
#         "function_code": "READ_HOLDING_REGISTERS",
#         "first_seen":    1700000500.0,
#         "packet_count":  3
#       }, ...
#     ],
#     "baseline_end": 1699990000.0
#   }

package guardance.new_edge

import future.keywords.if
import future.keywords.in

default violations := []

violations[result] if {
    edge := input.edges[_]
    edge.first_seen > input.baseline_end

    result := {
        "src_ip":        edge.src_ip,
        "dst_ip":        edge.dst_ip,
        "protocol":      edge.protocol,
        "port":          edge.port,
        "function_code": edge.function_code,
        "first_seen":    edge.first_seen,
        "packet_count":  edge.packet_count,
    }
}
