from incident_detector.services.utils import format_timedelta
from collections import defaultdict
from incident_detector.models import (
    DosIncident, 
)
from log_processor.models import (
    NetfilterPackets,
)

def detect_dos_attack(config):
    """
    Detects potential DoS attacks based on aggregated Netfilter packet data.
    Each NetfilterPackets entry represents a 30s window with a 'count' value.
    Uses a sliding window to detect high traffic within a configured time delta.
    """

    DOS_PACKET_THRESHOLD = config['packet_threshold']
    DOS_TIME_DELTA = config['time_delta']
    DOS_REPEAT_THRESHOLD = config['repeat_threshold']

    all_windows = NetfilterPackets.objects.all().order_by('timestamp')
    packets_by_connection = defaultdict(list)
    last_incident_time = {}
    incidents_created = 0
    new_incidents = []


    for window in all_windows:
        key = (window.src_ip_address, window.dst_ip_address, window.protocol)
        packets_by_connection[key].append(window)

    for (src_ip, dst_ip, protocol), windows in packets_by_connection.items():
        i = 0
        while i < len(windows):
            window_start = windows[i].timestamp
            window_end = window_start + DOS_TIME_DELTA

            
            relevant_windows = [w for w in windows if window_start <= w.timestamp <= window_end]
            total_packets = sum(w.count for w in relevant_windows)

            if total_packets >= DOS_PACKET_THRESHOLD:
                last_time = last_incident_time.get((src_ip, dst_ip, protocol))
                reason = f"{total_packets} packets in {format_timedelta(DOS_TIME_DELTA)}"

                existing_incident = DosIncident.objects.filter(
                    src_ip_address=src_ip,
                    dst_ip_address=dst_ip,
                    timestamp__gte=relevant_windows[-1].timestamp - DOS_REPEAT_THRESHOLD,
                    timestamp__lte=relevant_windows[-1].timestamp + DOS_REPEAT_THRESHOLD,
                    incident_type="dos",
                ).exists()

                if not existing_incident and (not last_time or window_start > last_time + DOS_REPEAT_THRESHOLD):
                    incident = DosIncident.objects.create(
                        timestamp=relevant_windows[-1].timestamp,
                        src_ip_address=src_ip,
                        dst_ip_address=dst_ip,
                        reason=reason,
                        incident_type="dos",
                        severity="high",
                        packets=total_packets,
                        timeDelta=format_timedelta(DOS_TIME_DELTA),
                        protocol=protocol,
                    )
                    last_incident_time[(src_ip, dst_ip, protocol)] = relevant_windows[-1].timestamp
                    incidents_created += 1
                    new_incidents.append(incident)

            
            i += 1

    return {
        "dos": incidents_created,
        "incidents": new_incidents
    }
