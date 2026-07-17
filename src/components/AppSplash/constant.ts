/**
 * 开屏中同时运动的小型雨燕数量。
 */
export const FLYING_BIRD_COUNT = 2;

/**
 * 常规动效主体展示时长（单位：毫秒）。
 * 与退场动画时长合计约 3 秒。
 */
export const SPLASH_VISIBLE_DURATION_MS = 2660;

/**
 * 用户偏好减少动态效果时的主体展示时长（单位：毫秒）。
 */
export const REDUCED_MOTION_VISIBLE_DURATION_MS = 650;

/**
 * 开屏退场动画和组件卸载之间的等待时长（单位：毫秒）。
 * 必须与 CSS 中的 transition 时长保持一致。
 */
export const SPLASH_REMOVE_DELAY_MS = 340;
