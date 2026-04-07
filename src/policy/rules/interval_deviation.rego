# interval_deviation.rego — detect polling intervals outside the expected range.
#
# Input schema:
#
#   {
#     "edges": [
#       {
#         "src_ip":          "192.168.1.10",
#         "dst_ip":          "10.0.0.1",
#         "protocol":        "modbus",
#         "port":            502,
#         "function_code":   "READ_HOLDING_REGISTERS",
#         "avg_interval_ms": 50.0,
#         "packet_count":    200,
#         "is_periodic":     false
#       }, ...
#     ],
#     "min_ms": 100.0,
#     "max_ms": 1000.0
#   }

package guardance.interval_deviation

import future.keywords.if
import future.keywords.in

default violations := []

violations[result] if {
    edge := input.edges[_]
    edge.packet_count > 1

    # Interval outside allowed window
    edge.avg_interval_ms < input.min_ms

    result := {
        "src_ip":          edge.src_ip,
        "dst_ip":          edge.dst_ip,
        "protocol":        edge.protocol,
        "port":            edge.port,
        "function_code":   edge.function_code,
        "avg_interval_ms": edge.avg_interval_ms,
        "packet_count":    edge.packet_count,
        "is_periodic":     edge.is_periodic,
        "reason":          "below_minimum",
    }
}

violations[result] if {
    edge := input.edges[_]
    edge.packet_count > 1

    edge.avg_interval_ms > input.max_ms

    result := {
        "src_ip":          edge.src_ip,
        "dst_ip":          edge.dst_ip,
        "protocol":        edge.protocol,
        "port":            edge.port,
        "function_code":   edge.function_code,
        "avg_interval_ms": edge.avg_interval_ms,
        "packet_count":    edge.packet_count,
        "is_periodic":     edge.is_periodic,
        "reason":          "above_maximum",
    }
}
