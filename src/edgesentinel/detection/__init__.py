"""Detection engine package for EdgeSentinel."""

from edgesentinel.detection.base import BaseDetector
from edgesentinel.detection.port_scan import PortScanDetector
from edgesentinel.detection.syn_anomaly import SynAnomalyDetector
from edgesentinel.detection.ssh_bruteforce import SshBruteforceDetector
from edgesentinel.detection.dns_anomaly import DnsAnomalyDetector
from edgesentinel.detection.arp_anomaly import ArpAnomalyDetector
from edgesentinel.detection.traffic_anomaly import TrafficAnomalyDetector
from edgesentinel.detection.new_device import NewDeviceDetector

__all__ = [
    "BaseDetector",
    "PortScanDetector",
    "SynAnomalyDetector",
    "SshBruteforceDetector",
    "DnsAnomalyDetector",
    "ArpAnomalyDetector",
    "TrafficAnomalyDetector",
    "NewDeviceDetector",
]
