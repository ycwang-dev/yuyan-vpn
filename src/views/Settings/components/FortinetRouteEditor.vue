<script setup lang="ts">
import { computed, ref } from 'vue';
import { PlusOutlined } from '@ant-design/icons-vue';
import { message } from 'ant-design-vue';
import { normalizeIpv4Cidr } from '../constant';

/** Fortinet 路由编辑器属性。 */
interface Props {
  modelValue: string[];
  builtInRoutes: readonly string[];
}

/** Fortinet 路由编辑器事件。 */
interface Emits {
  'update:modelValue': [routes: string[]];
}

const props = defineProps<Props>();
const emit = defineEmits<Emits>();
const routeInput = ref('');

/** 用户可删除的附加路由。 */
const additionalRoutes = computed(() => (
  props.modelValue.filter((route) => !props.builtInRoutes.includes(route))
));

/** 新增并规范化一条附加路由。 */
const addRoute = () => {
  const route = normalizeIpv4Cidr(routeInput.value);
  if (!route) {
    message.warning('请输入有效的 IPv4 CIDR，例如 192.168.111.0/24');
    return;
  }
  if (props.modelValue.includes(route)) {
    message.info('该路由已存在');
    return;
  }

  emit('update:modelValue', [...props.modelValue, route]);
  routeInput.value = '';
};

/** 删除指定附加路由，内置路由不会进入该操作。 */
const removeRoute = (route: string) => {
  emit('update:modelValue', props.modelValue.filter((item) => item !== route));
};
</script>

<template>
  <div class="fortinet-route-editor">
    <div class="route-group">
      <span class="route-group-label">内置路由</span>
      <a-tag v-for="route in builtInRoutes" :key="route" color="purple">
        {{ route }}
      </a-tag>
    </div>

    <div class="route-group">
      <span class="route-group-label">附加路由</span>
      <a-tag
        v-for="route in additionalRoutes"
        :key="route"
        closable
        @close.prevent="removeRoute(route)"
      >
        {{ route }}
      </a-tag>
      <span v-if="additionalRoutes.length === 0" class="route-empty">暂未配置</span>
    </div>

    <div class="route-input-row">
      <a-input
        v-model:value="routeInput"
        allow-clear
        placeholder="输入附加网段，例如 192.168.111.0/24"
        @press-enter="addRoute"
      />
      <a-button type="primary" ghost @click="addRoute">
        <template #icon><PlusOutlined /></template>
        添加路由
      </a-button>
    </div>

    <div class="route-help">
      路由按目标 IP 生效，与端口无关；如只开放单台主机，可填写 192.168.111.64/32。
      保存后请断开并重新连接 Fortinet。
    </div>
  </div>
</template>

<style scoped lang="less">
@import './style.less';
</style>
