import { ref } from 'vue';
import { listen } from '@tauri-apps/api/event';

export interface VpnLog {
  vpnType: 'fortinet' | 'atrust';
  text: string;
  time: string;
}

const logs = ref<VpnLog[]>([]);
const maxLogLines = 1000;
let isListening = false;

/** 提供 VPN 日志的共享状态、手动写入和原生事件监听能力。 */
export function useVpnLogs() {
  /** 追加一条日志，并限制内存中的最大日志行数。 */
  const appendLog = (vpnType: VpnLog['vpnType'], text: string) => {
    logs.value.push({
      vpnType,
      text,
      time: new Date().toLocaleTimeString(),
    });

    if (logs.value.length > maxLogLines) {
      logs.value.shift();
    }
  };

  /** 返回当前日志列表。 */
  const getLogs = () => logs.value;

  /** 清空当前日志列表。 */
  const clearLogs = () => {
    logs.value = [];
  };

  /** 监听 Rust 后端发送的 VPN 日志事件。 */
  const initLogListener = async () => {
    if (isListening) return;
    isListening = true;

    try {
      await listen<{ vpn_type: string; text: string }>('vpn-log', (event) => {
        const payload = event.payload;
        appendLog(payload.vpn_type === 'Fortinet' ? 'fortinet' : 'atrust', payload.text);
      });
      console.log('Tauri vpn-log event listener initialized successfully.');
    } catch (e) {
      console.error('Failed to register Tauri log listener:', e);
      isListening = false;
    }
  };

  return {
    logs,
    clearLogs,
    appendLog,
    initLogListener,
    getLogs,
  };
}
