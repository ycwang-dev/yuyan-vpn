<script setup lang="ts">
import UpdateCapsule from '@/components/UpdateCapsule/index.vue';
import { useAppUpdate } from '@/components/UpdateCapsule/hooks/useAppUpdate';
import { useTheme } from '@/hooks/useTheme';
import {
  BgColorsOutlined,
  InfoCircleOutlined,
  CloudDownloadOutlined,
  UserOutlined,
  LogoutOutlined,
} from '@ant-design/icons-vue';

defineOptions({ name: 'LayoutHeader' });

defineProps<{
  /** 是否是 Tauri 客户端 */
  isTauriClient: boolean;
}>();

defineEmits<{
  /** 触发打开平台设置抽屉 */
  (e: 'openSettings'): void;
  /** 触发打开关于雨燕弹窗 */
  (e: 'openAbout'): void;
}>();

const { isDark } = useTheme();
const { handleCheckUpdateClick } = useAppUpdate();

/** 退出当前登录/应用逻辑。 */
const handleLogout = async () => {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('exit_app');
  } catch (e) {
    console.error('退出应用失败:', e);
  }
};
</script>

<template>
  <a-layout-header class="yuyan-layout-header" :class="{ 'is-dark': isDark }">
    <div class="yuyan-layout-header-left">
      <!-- 赛博玻璃拟态更新胶囊 -->
      <UpdateCapsule v-if="isTauriClient" />
    </div>

    <div v-if="isTauriClient" class="yuyan-layout-header-drag" data-tauri-drag-region />

    <div class="yuyan-layout-header-right">
      <!-- 平台设置 -->
      <a-tooltip title="平台设置" overlayClassName="header-tooltip">
        <a-button type="text" class="header-action-btn btn-settings" @click="$emit('openSettings')">
          <template #icon>
            <BgColorsOutlined class="action-icon" />
          </template>
        </a-button>
      </a-tooltip>

      <!-- 用户头像下拉菜单 -->
      <div class="user-section">
        <a-dropdown :trigger="['hover']" placement="bottomRight" :overlayClassName="isDark ? 'header-user-dropdown is-dark' : 'header-user-dropdown'">
          <div class="user-dropdown-trigger">
            <div class="user-avatar">
              <img src="@/assets/avatar.png" alt="Avatar" />
            </div>
            <span class="user-name">管理员</span>
          </div>
          <template #overlay>
            <a-menu class="user-dropdown-menu">
              <a-menu-item v-if="isTauriClient" key="check-update" @click="handleCheckUpdateClick">
                <template #icon>
                  <CloudDownloadOutlined />
                </template>
                检查更新
              </a-menu-item>

              <a-menu-item v-if="isTauriClient" key="about" @click="$emit('openAbout')">
                <template #icon>
                  <InfoCircleOutlined />
                </template>
                关于平台
              </a-menu-item>

              <a-menu-divider />

              <a-menu-item key="profile" disabled>
                <template #icon>
                  <UserOutlined />
                </template>
                用户资料
              </a-menu-item>

              <a-menu-divider />

              <a-menu-item key="logout" @click="handleLogout">
                <template #icon>
                  <LogoutOutlined />
                </template>
                退出登录
              </a-menu-item>
            </a-menu>
          </template>
        </a-dropdown>
      </div>
    </div>
  </a-layout-header>
</template>

<style lang="less">
@import './style.less';
</style>
