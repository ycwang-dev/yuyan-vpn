import { onMounted, onUnmounted } from 'vue';
import { message } from 'ant-design-vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { isTauri } from '@/utils/env';

/** 安全退出清理事件载荷。 */
interface SafeExitStatusPayload {
  success: boolean;
  message: string;
}

/** 监听原生安全退出失败事件，并提示用户先处理残留进程。 */
export const useSafeExitNotice = () => {
  let unlisten: UnlistenFn | undefined;

  onMounted(async () => {
    if (!isTauri()) return;
    unlisten = await listen<SafeExitStatusPayload>('app-exit-cleanup-status', ({ payload }) => {
      if (!payload.success) {
        message.error({
          content: payload.message || 'VPN 清理失败，已阻止应用退出',
          duration: 0,
        });
      }
    });
  });

  onUnmounted(() => {
    unlisten?.();
  });
};
