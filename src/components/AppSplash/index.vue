<script setup lang="ts">
import { FLYING_BIRD_COUNT } from './constant';
import { useSplash } from './hooks/useSplash';

defineOptions({ name: 'AppSplash' });

const emit = defineEmits<{
  /**
   * 动效完全卸载退场时的回调事件。
   */
  finished: [];
}>();

const { visible, finish } = useSplash(() => {
  emit('finished');
});
</script>

<template>
  <Transition name="splash-fade">
    <section v-if="visible" class="swift-splash" aria-label="雨燕 SwiftVPN 正在启动">
      <div class="ambient ambient--violet" />
      <div class="ambient ambient--cyan" />
      <div class="star-field" />
      <div class="orbit orbit--one" />
      <div class="orbit orbit--two" />

      <div class="flight-layer" aria-hidden="true">
        <div
          v-for="bird in FLYING_BIRD_COUNT"
          :key="bird"
          class="flying-bird"
          :class="`flying-bird--${bird}`"
        >
          <img src="@/assets/logo.png" alt="flying bird" class="bird-image" />
          <span class="speed-line" />
        </div>
        <div class="flying-bird flying-bird--hero">
          <img src="@/assets/logo.png" alt="flying bird" class="bird-image" />
          <span class="speed-line" />
        </div>
      </div>

      <div class="brand-stage">
        <div class="icon-shell">
          <div class="icon-surface">
            <img src="@/assets/logo.png" alt="logo" class="brand-logo-image" />
          </div>
        </div>
        <div class="brand-copy">
          <p class="eyebrow">APODIDAE · BORN FOR SPEED</p>
          <h1>SWIFT</h1>
          <div class="platform"><span />VPN<span /></div>
          <p class="tagline">SECURE CONNECT. EXPLORE FREELY.</p>
        </div>
      </div>

      <button class="skip-button" type="button" aria-label="跳过开屏动画" @click="finish">
        SKIP <span />
      </button>
    </section>
  </Transition>
</template>

<style scoped lang="less">
@import './style.less';
</style>
