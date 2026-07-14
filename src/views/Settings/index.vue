<script setup lang="ts">
import {
  SettingOutlined,
  DashboardOutlined,
  SafetyOutlined,
  SaveOutlined,
  ReloadOutlined,
} from '@ant-design/icons-vue';
import { useVpnSettings } from './hooks/useVpnSettings';
import FortinetRouteEditor from './components/FortinetRouteEditor.vue';
import { BUILT_IN_FORTINET_ROUTES } from './constant';

defineOptions({ name: 'VpnSettings' });

const {
  formState,
  loading,
  saving,
  saveConfig,
  loadConfig,
} = useVpnSettings();
</script>

<template>
  <div class="settings-container">
    <div class="settings-header" data-tauri-drag-region>
      <h1>VPN 登录信息</h1>
    </div>

    <a-spin :spinning="loading">
      <!-- 1. Fortinet 配置块 -->
      <div class="settings-glass-card">
        <div class="section-title">
          <DashboardOutlined />
          北京服务器 VPN（Fortinet）
        </div>
        
        <a-form layout="vertical">
          <a-row :gutter="24">
            <a-col :span="12">
              <a-form-item label="网关主机">
                <a-input v-model:value="formState.fortinetHost" placeholder="例如 fortinet.example.com" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="网关端口">
                <a-input-number v-model:value="formState.fortinetPort" style="width: 100%" placeholder="例如 443" />
              </a-form-item>
            </a-col>
          </a-row>

          <a-row :gutter="24">
            <a-col :span="12">
              <a-form-item label="登录账号">
                <a-input v-model:value="formState.fortinetUsername" placeholder="请输入 VPN 登录账号" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="登录密码">
                <a-input-password v-model:value="formState.fortinetPassword" placeholder="请输入 VPN 登录密码" />
              </a-form-item>
            </a-col>
          </a-row>

          <a-row :gutter="24">
            <a-col :span="24">
              <a-form-item label="北京内网路由">
                <FortinetRouteEditor
                  v-model="formState.fortinetRoutes"
                  :built-in-routes="BUILT_IN_FORTINET_ROUTES"
                />
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </div>

      <!-- 2. aTrust 配置块 -->
      <div class="settings-glass-card">
        <div class="section-title">
          <SafetyOutlined />
          长沙服务器 VPN（aTrust）
        </div>

        <a-form layout="vertical">
          <a-row :gutter="24">
            <a-col :span="12">
              <a-form-item label="网关主机">
                <a-input v-model:value="formState.atrustHost" placeholder="例如 atrust.example.com" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="网关端口">
                <a-input-number v-model:value="formState.atrustPort" style="width: 100%" placeholder="例如 443" />
              </a-form-item>
            </a-col>
          </a-row>

          <a-row :gutter="24">
            <a-col :span="12">
              <a-form-item label="登录账号">
                <a-input v-model:value="formState.atrustUsername" placeholder="请输入 aTrust 登录账号" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item label="登录密码">
                <a-input-password v-model:value="formState.atrustPassword" placeholder="请输入 aTrust 登录密码" />
              </a-form-item>
            </a-col>
          </a-row>

          <a-alert
            type="info"
            show-icon
            message="长沙内网路由由服务器自动下发，无需手工配置"
          />
        </a-form>
      </div>

      <!-- 保存操作栏 -->
      <div class="settings-footer">
        <a-button @click="loadConfig">
          <template #icon><ReloadOutlined /></template>
          放弃更改
        </a-button>
        <a-button type="primary" :loading="saving" @click="saveConfig">
          <template #icon><SaveOutlined /></template>
          保存配置
        </a-button>
      </div>
    </a-spin>
  </div>
</template>

<style scoped lang="less">
@import './style.less';
</style>
