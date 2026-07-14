const envRoutes = import.meta.env.VITE_DEFAULT_FORTINET_ROUTES;
/** Fortinet 默认内网路由，仅由正式构建参数注入并始终随应用启用。 */
export const BUILT_IN_FORTINET_ROUTES = envRoutes
  ? (envRoutes.split(',').map((r: string) => r.trim()) as string[])
  : [];

/** VPN 设置表单模型。 */
export interface VpnSettingsForm {
  fortinetHost: string;
  fortinetPort: number;
  fortinetUsername: string;
  fortinetPassword?: string;
  fortinetRoutes: string[];

  atrustHost: string;
  atrustPort: number;
  atrustUsername: string;
  atrustPassword?: string;
  atrustRoutes: string; // 长沙内网路由由服务端自动下发，此字段仅兼容旧配置
}

/** VPN 设置页默认表单值。 */
export const DEFAULT_FORM_STATE: VpnSettingsForm = {
  fortinetHost: import.meta.env.VITE_DEFAULT_FORTINET_HOST || 'fortinet.example.com',
  fortinetPort: Number(import.meta.env.VITE_DEFAULT_FORTINET_PORT) || 443,
  fortinetUsername: import.meta.env.VITE_DEFAULT_FORTINET_USERNAME || 'sslvpn',
  fortinetPassword: '',
  fortinetRoutes: [...BUILT_IN_FORTINET_ROUTES],

  atrustHost: import.meta.env.VITE_DEFAULT_ATRUST_HOST || 'atrust.example.com',
  atrustPort: Number(import.meta.env.VITE_DEFAULT_ATRUST_PORT) || 443,
  atrustUsername: import.meta.env.VITE_DEFAULT_ATRUST_USERNAME || 'atrustvpn',
  atrustPassword: '',
  atrustRoutes: '',
};

/**
 * 校验并规范化 IPv4 CIDR，自动将带主机位的地址归一到网段地址。
 *
 * @param value 用户输入的 IPv4 CIDR，例如 `192.168.111.0/24`
 * @returns 规范化后的 CIDR；格式无效时返回 `null`
 */
export const normalizeIpv4Cidr = (value: string): string | null => {
  const [address, prefixText, ...rest] = value.trim().split('/');
  const octets = address?.split('.').map(Number) ?? [];
  const prefix = Number(prefixText);

  if (
    rest.length > 0
    || octets.length !== 4
    || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
    || !Number.isInteger(prefix)
    || prefix < 1
    || prefix > 32
  ) {
    return null;
  }

  const addressValue = octets.reduce((result, octet) => ((result << 8) | octet) >>> 0, 0);
  const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  const networkValue = (addressValue & mask) >>> 0;
  const networkAddress = [24, 16, 8, 0]
    .map((offset) => (networkValue >>> offset) & 0xff)
    .join('.');

  return `${networkAddress}/${prefix}`;
};
