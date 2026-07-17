import { ref, onMounted, onBeforeUnmount } from 'vue';
import {
  REDUCED_MOTION_VISIBLE_DURATION_MS,
  SPLASH_VISIBLE_DURATION_MS,
  SPLASH_REMOVE_DELAY_MS,
} from '../constant';

/**
 * 状态管理和退场定时器逻辑。
 * @param {() => void} onFinished - 动效彻底结束并被卸载时的回调
 * @returns {object} 返回控制开屏显隐状态及手动跳过的方法
 */
export function useSplash(onFinished: () => void) {
  const visible = ref(true);
  let finishTimer: ReturnType<typeof setTimeout> | undefined;
  let removeTimer: ReturnType<typeof setTimeout> | undefined;

  /**
   * 结束开屏动画并在退场动画完成后触发 finished 回调。
   */
  const finish = (): void => {
    if (!visible.value) return;

    visible.value = false;
    if (finishTimer) clearTimeout(finishTimer);
    removeTimer = setTimeout(() => {
      onFinished();
    }, SPLASH_REMOVE_DELAY_MS);
  };

  onMounted(() => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const visibleDuration = prefersReducedMotion
      ? REDUCED_MOTION_VISIBLE_DURATION_MS
      : SPLASH_VISIBLE_DURATION_MS;

    finishTimer = setTimeout(finish, visibleDuration);
  });

  onBeforeUnmount(() => {
    if (finishTimer) clearTimeout(finishTimer);
    if (removeTimer) clearTimeout(removeTimer);
  });

  return {
    visible,
    finish,
  };
}
