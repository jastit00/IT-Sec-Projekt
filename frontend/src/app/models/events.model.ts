export interface Events {
  id: number;
  timestamp: string;
  event_type: string;
  severity: string;
  source_ips?: string[];
  details?: any;
  
 
  reason?: string;
  ipAddress?: string;  
  action?: string;
  result?: string;     
}