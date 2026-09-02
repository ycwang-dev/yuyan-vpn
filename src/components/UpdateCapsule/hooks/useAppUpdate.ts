import { computed, onMounted, onUnmounted, ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { relaunch } from '@tauri-apps/plugin-process';
import {
  check,
  type DownloadEvent,
  type Update,
} from '@tauri-apps/plugin-updater';
import { message } from 'ant-design-vue';
import { isTauri } from '@/utils/env';
import { detectPlatform } from '@/utils/platformDetect';
import type { UpdateState } from '../constant';
import {
  AUTO_CHECK_INTERVAL_MS,
  INITIAL_CHECK_DELAY_MS,
  INSTALL_REVALIDATION_RETRY_DELAYS_MS,
  SILENT_DOWNLOAD_RETRY_DELAYS_MS,
} from '../constant';

/** 是否展示已完成验签、可由用户安装的更新胶囊。 */
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
/** 当前更新资源代次，用于丢弃已过期的异步下载结果。 */
let updateResourceGeneration = 0;
/** 当前下载尝试代次，用于丢弃重试前的异步进度。 */
let downloadAttemptGeneration = 0;
/** 当前更新检查代次，用于隔离安装动作开始前的迟到请求。 */
let updateCheckGeneration = 0;
/** 当前更新资源已执行的静默重试次数。 */
let silentDownloadRetryCount = 0;
/** 静默下载重试定时器。 */
let silentDownloadRetryTimer: ReturnType<typeof setTimeout> | null = null;
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

/** 为界面和提示统一补齐版本号的 `v` 前缀。 */
const formatVersion = (version: string): string => {
  if (!version) return '';
  return version.startsWith('v') ? version : `v${version}`;
};

/** 重置下载统计并进入指定状态。 */
const resetUpdateState = (
  status: UpdateState['status'],
  error: string | null = null,
) => {
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

/** 清除等待中的静默下载重试。 */
const clearSilentDownloadRetry = () => {
  if (silentDownloadRetryTimer) clearTimeout(silentDownloadRetryTimer);
  silentDownloadRetryTimer = null;
};

/** 安全释放一个 Tauri updater 资源。 */
const closeUpdateResource = async (update: Update | null) => {
  if (!update) return;
  try {
    await update.close();
  } catch (error) {
    console.warn('[Update] 释放更新资源失败:', error);
  }
};

/**
 * 从 Tauri 原始清单中提取更新资产身份。
 * 同版本资产的 URL 或签名发生变化时必须重新下载，不能复用旧字节资源。
 */
const getUpdateAssetFingerprint = (update: Update): string => {
  const rawJson = update.rawJson as Record<string, unknown>;
  const platforms = rawJson.platforms;
  if (platforms && typeof platforms === 'object') {
    const assets = Object.entries(platforms as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([platform, value]) => {
        const asset = value && typeof value === 'object'
          ? value as Record<string, unknown>
          : {};
        return [platform, asset.url ?? '', asset.signature ?? ''];
      });
    return JSON.stringify(assets);
  }
  return JSON.stringify([rawJson.url ?? '', rawJson.signature ?? '']);
};

/** 判断两次清单检查是否指向完全相同的签名更新资源。 */
const isSameUpdateResource = (left: Update, right: Update): boolean => {
  return left.version === right.version
    && getUpdateAssetFingerprint(left) === getUpdateAssetFingerprint(right);
};

/** 等待指定时间后继续更新流程。 */
const waitForUpdateRetry = (delayMs: number): Promise<void> => {
  return new Promise((resolve) => setTimeout(resolve, delayMs));
};

/**
 * 安装前复核更新清单，并自动吸收 GitHub Release 链路的瞬时网络失败。
 * @returns 最新可用更新；当前已是最新版本时返回 `null`
 */
const checkReadyUpdateWithRetry = async (): Promise<Update | null> => {
  let lastError: unknown;
  const maxAttempts = INSTALL_REVALIDATION_RETRY_DELAYS_MS.length + 1;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      return await check({ timeout: 15_000 });
    } catch (error) {
      lastError = error;
      const retryDelay = INSTALL_REVALIDATION_RETRY_DELAYS_MS[attempt];
      if (retryDelay === undefined) break;

      console.warn(
        `[Update] 安装前清单复核第 ${attempt + 1} 次失败，${retryDelay}ms 后重试:`,
        error,
      );
      message.loading({
        content: `更新信息暂时无法确认，正在重试（${attempt + 2}/${maxAttempts}）...`,
        duration: 0,
        key: 'app-update-install',
      });
      await waitForUpdateRetry(retryDelay);
    }
  }

  throw lastError ?? new Error('更新清单复核失败');
};

/** 用最新清单资源替换当前待安装资源。 */
const replacePendingUpdate = async (update: Update) => {
  const previousUpdate = pendingUpdate;
  pendingUpdate = update;
  updateResourceGeneration += 1;
  downloadAttemptGeneration += 1;
  silentDownloadRetryCount = 0;
  clearSilentDownloadRetry();
  hasUpdate.value = false;
  latestVersion.value = update.version;
  updateLogs.value = update.body || '无更新内容描述。';
  resetUpdateState('idle');
  await closeUpdateResource(previousUpdate);
};

/** 清理当前待安装资源和所有相关展示状态。 */
const clearPendingUpdate = async () => {
  const previousUpdate = pendingUpdate;
  pendingUpdate = null;
  updateResourceGeneration += 1;
  downloadAttemptGeneration += 1;
  silentDownloadRetryCount = 0;
  clearSilentDownloadRetry();
  hasUpdate.value = false;
  latestVersion.value = '';
  updateLogs.value = '';
  resetUpdateState('idle');
  await closeUpdateResource(previousUpdate);
};

/** 判断异步下载回调是否仍属于当前资源和当前尝试。 */
const isCurrentDownloadAttempt = (
  update: Update,
  resourceGeneration: number,
  attemptGeneration: number,
) => {
  return pendingUpdate === update
    && resourceGeneration === updateResourceGeneration
    && attemptGeneration === downloadAttemptGeneration;
};

/** 根据 Tauri updater 下载事件更新进度、速度和预计剩余时间。 */
const createDownloadProgressHandler = (
  update: Update,
  resourceGeneration: number,
  attemptGeneration: number,
) => {
  const startedAt = performance.now();

  return (event: DownloadEvent) => {
    if (!isCurrentDownloadAttempt(update, resourceGeneration, attemptGeneration)) return;
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

/** 安排下一次静默下载重试，自动失败期间不展示错误胶囊。 */
const scheduleSilentDownloadRetry = (
  update: Update,
  resourceGeneration: number,
) => {
  const retryDelay = SILENT_DOWNLOAD_RETRY_DELAYS_MS[silentDownloadRetryCount];
  if (retryDelay === undefined || pendingUpdate !== update) return;

  silentDownloadRetryCount += 1;
  clearSilentDownloadRetry();
  silentDownloadRetryTimer = setTimeout(() => {
    silentDownloadRetryTimer = null;
    if (pendingUpdate !== update || resourceGeneration !== updateResourceGeneration) return;
    void triggerUpdateDownload(false);
  }, retryDelay);
};

/** 使用 Tauri 官方 updater 在后台下载并验证签名更新包。 */
const triggerUpdateDownload = async (manual = false) => {
  const update = pendingUpdate;
  if (!update || updateState.value.status === 'downloading') return;
  if (updateState.value.status === 'installing') {
    if (manual) message.info('正在安装更新，请稍候');
    return;
  }

  if (manual) silentDownloadRetryCount = 0;
  clearSilentDownloadRetry();
  hasUpdate.value = false;
  resetUpdateState('downloading');
  const resourceGeneration = updateResourceGeneration;
  const attemptGeneration = ++downloadAttemptGeneration;

  try {
    await update.download(
      createDownloadProgressHandler(update, resourceGeneration, attemptGeneration),
      { timeout: 10 * 60 * 1000 },
    );
    if (!isCurrentDownloadAttempt(update, resourceGeneration, attemptGeneration)) return;

    updateState.value.status = 'completed';
    updateState.value.progress = 100;
    updateState.value.error = null;
    hasUpdate.value = true;
    silentDownloadRetryCount = 0;
    console.info(`[Update] 雨燕 ${formatVersion(latestVersion.value)} 已静默下载并通过签名校验`);
    if (manual) {
      message.success(`新版本 ${formatVersion(latestVersion.value)} 已准备完成，请点击顶部胶囊安装`);
    }
  } catch (error) {
    if (!isCurrentDownloadAttempt(update, resourceGeneration, attemptGeneration)) return;
    const errorMessage = getErrorMessage(error);
    resetUpdateState('error', errorMessage);
    hasUpdate.value = false;
    console.error('[Update] 静默下载或签名校验失败:', error);
    if (manual) message.error(`更新包准备失败：${errorMessage}`);
    scheduleSilentDownloadRetry(update, resourceGeneration);
  }
};

/**
 * 安装前重新确认远程清单仍指向当前已验签资源。
 * @returns 当前资源是否仍可直接安装
 */
const revalidateReadyUpdate = async (): Promise<boolean> => {
  const currentUpdate = pendingUpdate;
  const currentGeneration = updateResourceGeneration;
  if (!currentUpdate) return false;

  const refreshedUpdate = await checkReadyUpdateWithRetry();
  if (!refreshedUpdate) {
    await clearPendingUpdate();
    message.warning({
      content: '该更新版本已撤回或不再适用，已清理本机更新资源',
      key: 'app-update-install',
    });
    return false;
  }

  if (
    pendingUpdate === currentUpdate
    && currentGeneration === updateResourceGeneration
    && isSameUpdateResource(currentUpdate, refreshedUpdate)
  ) {
    updateLogs.value = refreshedUpdate.body || updateLogs.value;
    await closeUpdateResource(refreshedUpdate);
    return true;
  }

  await replacePendingUpdate(refreshedUpdate);
  message.info({
    content: `检测到更新版本 ${formatVersion(latestVersion.value)}，正在重新准备安装包`,
    key: 'app-update-install',
  });
  void triggerUpdateDownload(false);
  return false;
};

/** 安装已验证的更新包并请求 Tauri 安全重启。 */
const installReadyUpdate = async () => {
  if (!pendingUpdate || updateState.value.status !== 'completed') return;

  updateCheckGeneration += 1;
  updateState.value.status = 'installing';
  updateState.value.error = null;
  hasUpdate.value = false;

  try {
    message.loading({
      content: `正在确认 ${formatVersion(latestVersion.value)} 仍为有效更新...`,
      duration: 0,
      key: 'app-update-install',
    });
    if (!await revalidateReadyUpdate()) return;
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    console.error('[Update] 安装前清单复核失败:', error);
    updateState.value.status = 'completed';
    updateState.value.error = errorMessage;
    hasUpdate.value = true;
    message.error({
      content: `更新信息复核失败，已保留安装包，请稍后重试：${errorMessage}`,
      duration: 8,
      key: 'app-update-install',
    });
    return;
  }

  let vpnCleanupCompleted = false;
  try {
    const installableUpdate = pendingUpdate;
    if (!installableUpdate) throw new Error('已验证更新资源已失效，请重新检查更新');
    message.loading({
      content: '正在安全断开 VPN 并安装更新...',
      duration: 0,
      key: 'app-update-install',
    });
    await invoke('prepare_app_update_install');
    vpnCleanupCompleted = true;
    await installableUpdate.install();
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
    hasUpdate.value = true;
    message.error({
      content: `更新安装失败：${errorMessage}`,
      duration: 6,
      key: 'app-update-install',
    });
  }
};

/**
 * 使用配置的 `latest.json` 检查新版本。
 * @param manual 是否由用户手动触发
 */
const checkAppUpdate = async (manual = false) => {
  if (!isTauri()) return;
  if (detectPlatform().platform === 'windows') {
    if (manual) message.info('Windows VPN 仍处于候选验证阶段，暂不提供应用内更新');
    return;
  }
  if (checkingUpdate.value) {
    if (manual) message.info('正在检查更新，请稍候');
    return;
  }
  if (updateState.value.status === 'downloading') {
    if (manual) message.info(`新版本 ${formatVersion(latestVersion.value)} 正在后台准备，完成后会显示安装按钮`);
    return;
  }
  if (updateState.value.status === 'installing') {
    if (manual) message.info('正在安装更新，请稍候');
    return;
  }

  checkingUpdate.value = true;
  const checkGeneration = ++updateCheckGeneration;
  const hideLoading = manual ? message.loading('正在检查更新...', 0) : null;
  try {
    const foundUpdate = await check({ timeout: 15_000 });
    if (checkGeneration !== updateCheckGeneration) {
      await closeUpdateResource(foundUpdate);
      return;
    }
    if (!foundUpdate) {
      await clearPendingUpdate();
      if (manual) message.success('当前已是最新版本');
      return;
    }

    if (pendingUpdate && isSameUpdateResource(pendingUpdate, foundUpdate)) {
      updateLogs.value = foundUpdate.body || updateLogs.value;
      await closeUpdateResource(foundUpdate);
      if (updateState.value.status === 'completed') {
        hasUpdate.value = true;
        if (manual) {
          message.success(`新版本 ${formatVersion(latestVersion.value)} 已准备完成，请点击顶部胶囊安装`);
        }
        return;
      }
      if (manual) {
        message.info(`发现新版本 ${formatVersion(latestVersion.value)}，正在后台准备安装包`);
      }
      void triggerUpdateDownload(manual);
      return;
    }

    await replacePendingUpdate(foundUpdate);
    if (manual) {
      message.info(`发现新版本 ${formatVersion(latestVersion.value)}，正在后台准备安装包`);
    }
    void triggerUpdateDownload(manual);
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    console.error('[Update] 检查更新失败:', error);
    if (manual) message.error(`检查更新失败：${errorMessage}`);
  } finally {
    hideLoading?.();
    checkingUpdate.value = false;
  }
};

/** 处理用户在确认层中点击“立即安装”。 */
const handleCapsuleClick = () => {
  if (updateState.value.status === 'completed') {
    void installReadyUpdate();
    return;
  }
  if (updateState.value.status === 'installing') {
    message.info('正在安装更新并准备重启，请稍候');
  }
};

/** 处理菜单“检查更新”。 */
const handleCheckUpdateClick = () => {
  if (hasUpdate.value && updateState.value.status === 'completed') {
    message.success(`新版本 ${formatVersion(latestVersion.value)} 已准备完成，请点击顶部胶囊安装`);
    return;
  }
  if (pendingUpdate && updateState.value.status === 'downloading') {
    message.info(`新版本 ${formatVersion(latestVersion.value)} 正在后台准备，完成后会显示安装按钮`);
    return;
  }
  if (pendingUpdate && updateState.value.status === 'error') {
    void checkAppUpdate(true);
    return;
  }
  if (updateState.value.status === 'installing') {
    message.info('正在安装更新并准备重启，请稍候');
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
  clearSilentDownloadRetry();
  unlistenMenuCheckUpdate?.();
  unlistenMenuCheckUpdate = null;
};

/**
 * 自动更新单例 Composable。
 * @description 自动检查、后台下载和签名校验保持静默，仅在安装包就绪后展示胶囊。
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
    initialCheckTimer = setTimeout(() => {
      initialCheckTimer = null;
      void checkAppUpdate(false);
    }, INITIAL_CHECK_DELAY_MS);
    autoUpdateInterval = setInterval(() => void checkAppUpdate(false), AUTO_CHECK_INTERVAL_MS);
  });

  onUnmounted(() => {
    instanceCount = Math.max(0, instanceCount - 1);
    if (instanceCount === 0) clearUpdateLifecycle();
  });

  return {
    /** 是否展示已就绪更新胶囊 */
    hasUpdate,
    /** 当前更新状态 */
    updateState,
    /** 当前下载进度 */
    updatePercent,
    /** 最新版本号 */
    latestVersion,
    /** 更新说明 */
    updateLogs,
    /** 是否正在检查更新 */
    checkingUpdate,
    /** 手动或自动检查更新 */
    checkAppUpdate,
    /** 确认安装已就绪更新 */
    handleCapsuleClick,
    /** 菜单检查更新 */
    handleCheckUpdateClick,
  };
};
