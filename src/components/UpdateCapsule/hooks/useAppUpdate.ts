import { computed, onMounted, onUnmounted, ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { relaunch } from '@tauri-apps/plugin-process';
import {
  check,
  type DownloadEvent,
  type Update,
} from '@tauri-apps/plugin-updater';
import { Modal, message } from 'ant-design-vue';
import { isTauri } from '@/utils/env';
import { detectPlatform } from '@/utils/platformDetect';
import type { UpdateState } from '../constant';
import {
  AUTO_CHECK_INTERVAL_MS,
  INITIAL_CHECK_DELAY_MS,
} from '../constant';

/** 当前是否发现可用更新。 */
const hasUpdate = ref(false);
/** 当前是否正在请求更新清单。 */
const checkingUpdate = ref(false);
/** 最新可用版本号。 */
const latestVersion = ref('');
/** 最新版本发布说明。 */
const updateLogs = ref('');
/** 更新胶囊共享状态。 */
const updateState = ref<UpdateState>({
  status: 'idle',
  progress: 0,
  error: null,
  downloadedBytes: 0,
  totalBytes: null,
  bytesPerSecond: 0,
  remainingSeconds: null,
});
/** 下载进度百分比。 */
const updatePercent = computed(() => updateState.value.progress);

/** Tauri updater 返回的待安装更新资源。 */
let pendingUpdate: Update | null = null;
/** 自动检查定时器。 */
let autoUpdateInterval: ReturnType<typeof setInterval> | null = null;
/** 首次检查延时器。 */
let initialCheckTimer: ReturnType<typeof setTimeout> | null = null;
/** macOS 系统菜单事件清理函数。 */
let unlistenMenuCheckUpdate: (() => void) | null = null;
/** 当前使用更新单例的组件数量。 */
let instanceCount = 0;

/** 将未知异常转换为可展示的中文错误。 */
const getErrorMessage = (error: unknown): string => {
  if (error instanceof Error) return error.message;
  return String(error || '未知错误');
};

/** 重置下载统计并进入指定状态。 */
const resetUpdateState = (status: UpdateState['status'], error: string | null = null) => {
  updateState.value = {
    status,
    progress: 0,
    error,
    downloadedBytes: 0,
    totalBytes: null,
    bytesPerSecond: 0,
    remainingSeconds: null,
  };
};

/** 根据 Tauri updater 下载事件更新进度、速度和预计剩余时间。 */
const createDownloadProgressHandler = () => {
  const startedAt = performance.now();

  return (event: DownloadEvent) => {
    if (event.event === 'Started') {
      updateState.value.totalBytes = event.data.contentLength ?? null;
      return;
    }
    if (event.event === 'Progress') {
      updateState.value.downloadedBytes += event.data.chunkLength;
      const elapsedSeconds = Math.max((performance.now() - startedAt) / 1000, 0.001);
      const speed = Math.round(updateState.value.downloadedBytes / elapsedSeconds);
      const total = updateState.value.totalBytes;
      updateState.value.bytesPerSecond = speed;
      updateState.value.progress = total
        ? Math.min(99, Math.round((updateState.value.downloadedBytes / total) * 100))
        : 0;
      updateState.value.remainingSeconds = total && speed > 0
        ? Math.max(0, Math.ceil((total - updateState.value.downloadedBytes) / speed))
        : null;
      return;
    }
    updateState.value.progress = 100;
    updateState.value.remainingSeconds = 0;
    updateState.value.bytesPerSecond = 0;
  };
};

/** 使用 Tauri 官方 updater 下载并验证签名更新包。 */
const triggerUpdateDownload = async () => {
  if (!pendingUpdate || updateState.value.status === 'downloading') return;

  resetUpdateState('downloading');
  try {
    await pendingUpdate.download(createDownloadProgressHandler(), { timeout: 10 * 60 * 1000 });
    updateState.value.status = 'completed';
    updateState.value.progress = 100;
    message.success(`雨燕 ${latestVersion.value} 已下载并通过签名校验，可随时重启更新`);
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    resetUpdateState('error', errorMessage);
    console.error('[Update] 下载或签名校验失败:', error);
  }
};

/** 安装已验证的更新包并请求 Tauri 安全重启。 */
const installAndRestart = async () => {
  if (!pendingUpdate || updateState.value.status !== 'completed') return;

  updateState.value.status = 'installing';
  let vpnCleanupCompleted = false;
  try {
    message.loading({
      content: '正在安全断开 VPN 并安装更新...',
      duration: 0,
      key: 'app-update-install',
    });
    await invoke('prepare_app_update_install');
    vpnCleanupCompleted = true;
    await pendingUpdate.install();
    message.success({
      content: '更新安装完成，正在重启雨燕...',
      duration: 2,
      key: 'app-update-install',
    });
    await relaunch();
  } catch (error) {
    if (vpnCleanupCompleted) {
      await invoke('cancel_app_update_install_preparation').catch((cancelError) => {
        console.error('[Update] 恢复 VPN 连接门禁失败:', cancelError);
      });
    }
    const errorMessage = getErrorMessage(error);
    updateState.value.status = 'completed';
    updateState.value.error = errorMessage;
    message.error({
      content: `更新安装失败：${errorMessage}`,
      duration: 6,
      key: 'app-update-install',
    });
  }
};

/** 请求用户确认立即重启安装。 */
const confirmInstallAndRestart = () => {
  Modal.confirm({
    title: `安装雨燕 ${latestVersion.value}`,
    content: '更新已下载并通过签名校验。继续后会安全断开 VPN、安装更新并重启应用。',
    okText: '立即重启更新',
    cancelText: '稍后',
    centered: true,
    onOk: installAndRestart,
  });
};

/**
 * 使用配置的 `latest.json` 检查新版本。
 * @param manual 是否由用户手动触发
 */
const checkAppUpdate = async (manual = false) => {
  if (!isTauri() || checkingUpdate.value) return;
  if (detectPlatform().platform === 'windows') {
    if (manual) message.info('Windows VPN 仍处于候选验证阶段，暂不提供应用内更新');
    return;
  }
  if (updateState.value.status === 'downloading') {
    if (manual) message.info('新版本正在后台下载中');
    return;
  }
  if (updateState.value.status === 'installing') {
    if (manual) message.info('正在安装更新，请稍候');
    return;
  }

  checkingUpdate.value = true;
  try {
    const foundUpdate = await check({ timeout: 15_000 });
    if (!foundUpdate) {
      if (pendingUpdate) {
        await pendingUpdate.close();
        pendingUpdate = null;
      }
      hasUpdate.value = false;
      if (manual) message.success('当前已是最新版本');
      return;
    }

    if (pendingUpdate?.version === foundUpdate.version) {
      await foundUpdate.close();
      if (updateState.value.status === 'completed' && manual) {
        confirmInstallAndRestart();
      }
      return;
    }

    if (pendingUpdate) await pendingUpdate.close();
    pendingUpdate = foundUpdate;
    hasUpdate.value = true;
    latestVersion.value = foundUpdate.version;
    updateLogs.value = foundUpdate.body || '无更新内容描述。';
    resetUpdateState('idle');
    void triggerUpdateDownload();
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    console.error('[Update] 检查更新失败:', error);
    if (manual) message.error(`检查更新失败：${errorMessage}`);
  } finally {
    checkingUpdate.value = false;
  }
};

/** 处理更新胶囊点击。 */
const handleCapsuleClick = () => {
  if (updateState.value.status === 'completed') {
    confirmInstallAndRestart();
    return;
  }
  if (updateState.value.status === 'error' || updateState.value.status === 'idle') {
    void triggerUpdateDownload();
  }
};

/** 处理菜单“检查更新”。 */
const handleCheckUpdateClick = () => {
  if (updateState.value.status === 'completed') {
    confirmInstallAndRestart();
    return;
  }
  void checkAppUpdate(true);
};

/** 清理自动更新生命周期资源。 */
const clearUpdateLifecycle = () => {
  if (initialCheckTimer) clearTimeout(initialCheckTimer);
  if (autoUpdateInterval) clearInterval(autoUpdateInterval);
  initialCheckTimer = null;
  autoUpdateInterval = null;
  unlistenMenuCheckUpdate?.();
  unlistenMenuCheckUpdate = null;
};

/**
 * 自动更新单例 Composable。
 * @returns 更新状态、进度以及手动操作入口
 */
export const useAppUpdate = () => {
  onMounted(() => {
    instanceCount += 1;
    if (instanceCount !== 1 || !isTauri()) return;

    import('@tauri-apps/api/event').then(({ listen }) => {
      listen('menu-check-update', handleCheckUpdateClick).then((unlisten) => {
        unlistenMenuCheckUpdate = unlisten;
      });
    });
    initialCheckTimer = setTimeout(() => void checkAppUpdate(false), INITIAL_CHECK_DELAY_MS);
    autoUpdateInterval = setInterval(() => void checkAppUpdate(false), AUTO_CHECK_INTERVAL_MS);
  });

  onUnmounted(() => {
    instanceCount = Math.max(0, instanceCount - 1);
    if (instanceCount === 0) clearUpdateLifecycle();
  });

  return {
    hasUpdate,
    updateState,
    updatePercent,
    latestVersion,
    updateLogs,
    checkingUpdate,
    checkAppUpdate,
    handleCapsuleClick,
    handleCheckUpdateClick,
  };
};
