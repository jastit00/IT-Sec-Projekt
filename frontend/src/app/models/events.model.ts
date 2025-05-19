export interface Events {
  ipAddress: string;
  id: number;
  timestamp: string;
  event_type: string;
  severity: string;
  source_ips: string[];
  details: any;
  reason: string;
  src_ip_address: string; 
  action: string;
  result: string;
  incident_type: string;
}