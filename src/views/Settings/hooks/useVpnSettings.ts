import { ref, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { message } from 'ant-design-vue';
import {
  type VpnSettingsForm,
  BUILT_IN_FORTINET_ROUTES,
  DEFAULT_FORM_STATE,
} from '../constant';

/**
 * 管理 VPN 设置页的加载、编辑和保存状态。
 *
 * @returns VPN 设置表单状态与操作方法
 */
export function useVpnSettings() {
  const formState = ref<VpnSettingsForm>({
    ...DEFAULT_FORM_STATE,
    fortinetRoutes: [...DEFAULT_FORM_STATE.fortinetRoutes],
  });
  const loading = ref(false);
  const saving = ref(false);

  /** 加载本地配置并映射到表单。 */
  const loadConfig = async () => {
    loading.value = true;
    try {
      const res = await invoke<{
        fortinet: {
          host: string;
          port: number;
          username: string;
          password?: string;
          customRoutes?: string[];
        };
        atrust: {
          host: string;
          port: number;
          username: string;
          password?: string;
          customRoutes?: string[];
        };
      }>('load_vpn_config');
      
      formState.value = {
        fortinetHost: res.fortinet.host,
        fortinetPort: res.fortinet.port,
        fortinetUsername: res.fortinet.username,
        fortinetPassword: res.fortinet.password ?? '',
        fortinetRoutes: res.fortinet.customRoutes?.length
          ? [...res.fortinet.customRoutes]
          : [...BUILT_IN_FORTINET_ROUTES],

        atrustHost: res.atrust.host,
        atrustPort: res.atrust.port,
        atrustUsername: res.atrust.username,
        atrustPassword: res.atrust.password ?? '',
        atrustRoutes: res.atrust.customRoutes?.join(', ') ?? '',
      };
    } catch (err: unknown) {
      message.error(`加载配置失败: ${String(err)}`);
    } finally {
      loading.value = false;
    }
  };

  /** 映射表单并保存本地配置。 */
  const saveConfig = async () => {
    saving.value = true;
    try {
      const settingsPayload = {
        fortinet: {
          enabled: true,
          host: formState.value.fortinetHost,
          port: formState.value.fortinetPort,
          username: formState.value.fortinetUsername,
          password: formState.value.fortinetPassword ?? '',
          savePassword: true,
          customRoutes: formState.value.fortinetRoutes,
        },
        atrust: {
          enabled: true,
          host: formState.value.atrustHost,
          port: formState.value.atrustPort,
          username: formState.value.atrustUsername,
          password: formState.value.atrustPassword ?? '',
          savePassword: true,
          customRoutes: formState.value.atrustRoutes
            .split(',')
            .map((route) => route.trim())
            .filter(Boolean),
        },
      };

      await invoke('save_vpn_config', { settings: settingsPayload });
      message.success('VPN 配置保存成功，附加路由将在下次连接 Fortinet 时生效');
    } catch (err: unknown) {
      message.error(`保存配置失败: ${String(err)}`);
    } finally {
      saving.value = false;
    }
  };

  onMounted(() => {
    void loadConfig();
  });

  return {
    formState,
    loading,
    saving,
    saveConfig,
    loadConfig,
  };
}
