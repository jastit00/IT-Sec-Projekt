
from collections import defaultdict
from incident_detector.services.utils import format_timedelta

from incident_detector.models import (
    DDosIncident,
)
from log_processor.models import (
    NetfilterPackets,
)

from collections import defaultdict

def detect_ddos_attack(config):
    DDOS_PACKET_THRESHOLD = config['packet_threshold']
    DDOS_TIME_DELTA = config['time_delta']
    DDOS_REPEAT_THRESHOLD = config['repeat_threshold']
    DDOS_MIN_SOURCES = config['min_sources']

    # implizite Gesamtpaketschwelle
    implied_total_packet_threshold = DDOS_PACKET_THRESHOLD * DDOS_MIN_SOURCES

    all_windows = NetfilterPackets.objects.all().order_by('timestamp')
    windows_by_dst_proto = defaultdict(list)
    last_incident_time = {}
    incidents_created = 0
    new_incidents = []

    for window in all_windows:
        key = (window.dst_ip_address, window.protocol)
        windows_by_dst_proto[key].append(window)

    for (dst_ip, protocol), windows in windows_by_dst_proto.items():
        i = 0
        while i < len(windows):
            window_start = windows[i].timestamp
            window_end = window_start + DDOS_TIME_DELTA

            relevant_windows = [w for w in windows[i:] if w.timestamp <= window_end]

            traffic_by_source = defaultdict(int)
            for win in relevant_windows:
                traffic_by_source[win.src_ip_address] += win.count

            active_sources = [src for src, count in traffic_by_source.items() if count >= DDOS_PACKET_THRESHOLD]
            total_packets = sum(traffic_by_source.values())

            low_traffic_many_sources = (
                len(traffic_by_source) >= DDOS_MIN_SOURCES and
                total_packets >= implied_total_packet_threshold
            )

            if len(active_sources) >= DDOS_MIN_SOURCES or low_traffic_many_sources:
                last_time = last_incident_time.get(dst_ip)

                reason = (
                    f"{len(active_sources)} sources sent >= {DDOS_PACKET_THRESHOLD} packets in {format_timedelta(DDOS_TIME_DELTA)}"
                    if len(active_sources) >= DDOS_MIN_SOURCES
                    else f"{len(traffic_by_source)} sources sent a total of {total_packets} packets in {format_timedelta(DDOS_TIME_DELTA)}"
                )

                existing_incident = DDosIncident.objects.filter(
                    dst_ip_address=dst_ip,
                    timestamp__range=(window_start, window_end),
                    incident_type="ddos"
                ).exists()

                if not existing_incident and (not last_time or window_start > last_time + DDOS_REPEAT_THRESHOLD):
                    clean_sources = [str(src) for src in traffic_by_source.keys() if src]
                    sources_str = ",".join(clean_sources) if clean_sources else "unknown"

                    incident = DDosIncident.objects.create(
                        timestamp=relevant_windows[-1].timestamp,
                        sources=sources_str,
                        dst_ip_address=dst_ip,
                        reason=reason,
                        incident_type="ddos",
                        severity="high",
                        packets=str(total_packets),
                        timeDelta=format_timedelta(DDOS_TIME_DELTA),
                        protocol=protocol,
                    )

                    last_incident_time[dst_ip] = relevant_windows[-1].timestamp
                    incidents_created += 1
                    new_incidents.append(incident)

                i += len(relevant_windows)
            else:
                i += 1

    return {
        "ddos": incidents_created,
        "incidents": new_incidents
    }
