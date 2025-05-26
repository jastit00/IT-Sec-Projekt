export interface Events {
  id: number;
  timestamp: string;
  event_type: string;
  severity: string;
  username: string;
  src_ip_address: string;
  terminal: string;
  result: string;
  reason: string;
  dst_ip_address: string;
  incident_type: string;
  protocol: string;
  table: string;
  action: string;
  key: string;
  value: string;
  condition: string;
  packets: string;
  timeDelta: string;
  source_ips: string[];
  details: any;
  count: number;
}