import { nextTick, onMounted, onUnmounted } from 'vue';
import { useRouter } from 'vue-router';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { message } from 'ant-design-vue';
import { isTauri } from '@/utils/env';

/** 前端内部事件：要求 Dashboard 继续完成托盘 VPN 动作。 */
export const TRAY_VPN_ACTION_EVENT = 'yuyan:tray-vpn-action';
/** 前端内部事件：转发 aTrust 二次认证提示。 */
export const VPN_AUTH_FORWARD_EVENT = 'yuyan:vpn-auth-required';
/** 前端内部事件：转发 aTrust 图形验证码。 */
export const VPN_CAPTCHA_FORWARD_EVENT = 'yuyan:vpn-captcha-required';

/** 托盘支持的 VPN 快捷动作。 */
export type TrayVpnAction = 'fortinet' | 'atrust' | 'both' | 'disconnectAll';

/** Rust 托盘导航事件载荷。 */
interface TrayNavigationPayload {
  path: string;
}

/** Rust 托盘前置条件事件载荷。 */
interface TrayActionRequiredPayload {
  action: TrayVpnAction;
  reason: 'authorization' | 'missingPassword';
  message: string;
  path: string;
}

/** Rust 托盘异步操作反馈载荷。 */
interface TrayFeedbackPayload {
  level: 'error' | 'warning' | 'info' | 'success';
  message: string;
}

/** aTrust 二次认证事件载荷。 */
export interface VpnAuthEventPayload {
  vpnType: 'Atrust';
  prompt?: string;
}

/** aTrust 图形验证码事件载荷。 */
export interface VpnCaptchaEventPayload {
  vpnType: 'Atrust';
  url: string;
}

/** Dashboard 接收的托盘动作事件载荷。 */
export interface TrayVpnActionEventPayload {
  action: TrayVpnAction;
}

/**
 * 连接原生托盘与 Vue 路由、权限弹窗及 MFA 弹窗。
 * @description 监听始终挂载在 App 根组件，确保主窗口隐藏或 Dashboard 未挂载时不丢事件。
 */
export const useTrayIntegration = () => {
  const router = useRouter();
  const unlisteners: UnlistenFn[] = [];
  let disposed = false;
  let navigationSequence = 0;

  /** 注册 Tauri 事件并处理监听器晚于组件销毁返回的竞态。 */
  const registerListener = async <T>(
    eventName: string,
    handler: (payload: T) => void | Promise<void>,
  ) => {
    try {
      const unlisten = await listen<T>(eventName, ({ payload }) => {
        void Promise.resolve(handler(payload)).catch((error) => {
          console.error(`[Tray] 处理 ${eventName} 事件失败:`, error);
        });
      });
      if (disposed) {
        unlisten();
        return;
      }
      unlisteners.push(unlisten);
    } catch (error) {
      console.error(`[Tray] 注册 ${eventName} 事件失败:`, error);
    }
  };

  /** 显示主窗口并切换到指定页面，过期导航不会继续派发业务事件。 */
  const revealAndNavigate = async (path: string): Promise<boolean> => {
    const currentSequence = ++navigationSequence;
    await invoke('show_main_window');
    if (currentSequence !== navigationSequence) return false;
    if (path && router.currentRoute.value.path !== path) {
      await router.push(path);
    }
    await nextTick();
    return currentSequence === navigationSequence;
  };

  /** 向目标页面派发浏览器内部事件。 */
  const dispatchWindowEvent = <T>(eventName: string, payload: T) => {
    window.dispatchEvent(new CustomEvent<T>(eventName, { detail: payload }));
  };

  /** 处理托盘导航。 */
  const handleTrayNavigation = async (payload: TrayNavigationPayload) => {
    try {
      await revealAndNavigate(payload.path || '/dashboard');
    } catch (error) {
      console.error('[Tray] 页面导航失败:', error);
      message.error('无法打开雨燕主界面');
    }
  };

  /** 处理托盘连接所缺少的登录信息或系统权限。 */
  const handleTrayActionRequired = async (payload: TrayActionRequiredPayload) => {
    try {
      const navigationCompleted = await revealAndNavigate(payload.path || '/dashboard');
      if (!navigationCompleted) return;
      if (payload.reason === 'missingPassword') {
        message.warning(payload.message || '请先补全 VPN 登录信息');
        return;
      }
      message.info(payload.message || '请先完成系统权限验证');
      dispatchWindowEvent<TrayVpnActionEventPayload>(TRAY_VPN_ACTION_EVENT, {
        action: payload.action,
      });
    } catch (error) {
      console.error('[Tray] 处理前置条件失败:', error);
      message.error('无法继续托盘 VPN 操作');
    }
  };

  /** 展示原生托盘异步操作反馈。 */
  const handleTrayFeedback = (payload: TrayFeedbackPayload) => {
    const content = payload.message || '托盘操作失败';
    if (payload.level === 'success') {
      message.success(content);
    } else if (payload.level === 'warning') {
      message.warning(content);
    } else if (payload.level === 'info') {
      message.info(content);
    } else {
      message.error({ content, duration: 0 });
    }
  };

  /** 唤起 Dashboard 并转发 aTrust 二次认证。 */
  const handleVpnAuthRequired = async (payload: VpnAuthEventPayload) => {
    if (payload.vpnType !== 'Atrust') return;
    if (await revealAndNavigate('/dashboard')) {
      dispatchWindowEvent(VPN_AUTH_FORWARD_EVENT, payload);
    }
  };

  /** 唤起 Dashboard 并转发 aTrust 图形验证码。 */
  const handleVpnCaptchaRequired = async (payload: VpnCaptchaEventPayload) => {
    if (payload.vpnType !== 'Atrust' || !payload.url) return;
    if (await revealAndNavigate('/dashboard')) {
      dispatchWindowEvent(VPN_CAPTCHA_FORWARD_EVENT, payload);
    }
  };

  onMounted(() => {
    if (!isTauri()) return;
    void registerListener<TrayNavigationPayload>('tray-navigate', handleTrayNavigation);
    void registerListener<TrayActionRequiredPayload>(
      'tray-action-required',
      handleTrayActionRequired,
    );
    void registerListener<TrayFeedbackPayload>('tray-operation-feedback', handleTrayFeedback);
    void registerListener<VpnAuthEventPayload>('vpn-auth-required', handleVpnAuthRequired);
    void registerListener<VpnCaptchaEventPayload>(
      'vpn-captcha-required',
      handleVpnCaptchaRequired,
    );
  });

  onUnmounted(() => {
    disposed = true;
    navigationSequence += 1;
    unlisteners.splice(0).forEach((unlisten) => unlisten());
  });
};
