# new_device.rego — detect devices first seen after the baseline period.
#
# Input schema:
#
#   {
#     "devices": {
#       "192.168.1.10": {
#         "ip":         "192.168.1.10",
#         "mac":        "aa:bb:cc:dd:ee:ff",
#         "role":       null,
#         "first_seen": 1700000000.0,
#         "last_seen":  1700001000.0
#       }, ...
#     },
#     "baseline_end": 1699990000.0
#   }

package guardance.new_device

import future.keywords.if
import future.keywords.in

default violations := []

violations[result] if {
    device := input.devices[_]
    device.first_seen > input.baseline_end

    result := {
        "ip":         device.ip,
        "mac":        device.mac,
        "role":       device.role,
        "first_seen": device.first_seen,
        "last_seen":  device.last_seen,
    }
}
