export interface VpnStats {
  status: 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'error' | 'authenticating';
  virtualIp: string | null;
  uptime: number;
  message: string;
}

export const VPN_TYPES = {
  FORTINET: 'fortinet',
  ATRUST: 'atrust',
} as const;

export const STATUS_LABELS: Record<string, string> = {
  disconnected: '已断开',
  connecting: '连接中...',
  connected: '已连接',
  disconnecting: '正在断开...',
  error: '连接错误',
};
