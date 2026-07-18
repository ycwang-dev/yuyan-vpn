import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, '..');
const REQUIRED_PATCH_MARKERS = [
  'stage: fortisslvpn_xml',
  'Legacy FortiOS VPN configuration accepted',
  'Tunnel ended; reconnecting',
  'TCP keepalive enabled',
  'PPP keepalive confirmed',
  'TLS transport ended while',
];

const ARCHITECTURE_POLICIES = {
  arm64: {
    engineKey: 'openfortivpnArm64',
    suffix: 'aarch64-apple-darwin',
    fileMarker: 'arm64',
  },
  x64: {
    engineKey: 'openfortivpnX64',
    suffix: 'x86_64-apple-darwin',
    fileMarker: 'x86_64',
  },
};

/** 读取当前 macOS 架构对应的引擎锁定策略。 */
export const resolveMacosEnginePolicy = ({
  architecture = process.arch,
  repositoryRoot = REPOSITORY_ROOT,
} = {}) => {
  const architecturePolicy = ARCHITECTURE_POLICIES[architecture];
  if (!architecturePolicy) {
    throw new Error(`不支持的 macOS Node.js 架构: ${architecture}`);
  }

  const lockPath = path.join(repositoryRoot, 'scripts', 'vpn-engines.lock.json');
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  const engine = lock.macos?.[architecturePolicy.engineKey];
  if (!engine?.version) {
    throw new Error(`引擎锁文件缺少 ${architecturePolicy.engineKey} 版本`);
  }

  return {
    ...architecturePolicy,
    version: engine.version,
    binaryPath: path.join(
      repositoryRoot,
      'src-tauri',
      'binaries',
      `openfortivpn-${architecturePolicy.suffix}`,
    ),
  };
};

/** 检查二进制版本、架构和所有雨燕补丁标记。 */
export const inspectMacosOpenfortivpn = ({
  binaryPath,
  expectedVersion,
  expectedFileMarker,
  requiredMarkers = REQUIRED_PATCH_MARKERS,
}) => {
  const problems = [];
  if (!fs.existsSync(binaryPath)) {
    return [`缺少二进制: ${binaryPath}`];
  }

  const fileMode = fs.statSync(binaryPath).mode;
  if ((fileMode & 0o111) === 0) {
    problems.push('二进制没有执行权限');
  }

  const versionResult = spawnSync(binaryPath, ['--version'], {
    encoding: 'utf8',
    timeout: 10_000,
  });
  const actualVersion = versionResult.stdout?.trim();
  if (versionResult.error || versionResult.status !== 0) {
    problems.push(`无法执行 --version: ${versionResult.error?.message ?? versionResult.stderr?.trim() ?? '未知错误'}`);
  } else if (actualVersion !== expectedVersion) {
    problems.push(`版本不匹配: 期望 ${expectedVersion}，实际 ${actualVersion || '空'}`);
  }

  if (expectedFileMarker) {
    const fileResult = spawnSync('/usr/bin/file', ['-b', binaryPath], {
      encoding: 'utf8',
      timeout: 10_000,
    });
    if (fileResult.error || fileResult.status !== 0) {
      problems.push(`无法识别二进制架构: ${fileResult.error?.message ?? fileResult.stderr?.trim() ?? '未知错误'}`);
    } else if (!fileResult.stdout.includes(expectedFileMarker)) {
      problems.push(`架构不匹配: 期望 ${expectedFileMarker}，实际 ${fileResult.stdout.trim()}`);
    }
  }

  const binary = fs.readFileSync(binaryPath);
  for (const marker of requiredMarkers) {
    if (!binary.includes(Buffer.from(marker))) {
      problems.push(`缺少补丁标记: ${marker}`);
    }
  }

  return problems;
};

/** 在 Tauri 打包前自动重建过期引擎，并对构建结果执行硬性复核。 */
export const prepareMacosOpenfortivpn = ({
  platform = process.platform,
  architecture = process.arch,
  repositoryRoot = REPOSITORY_ROOT,
  checkOnly = false,
} = {}) => {
  if (platform !== 'darwin') {
    return { skipped: true };
  }

  const policy = resolveMacosEnginePolicy({ architecture, repositoryRoot });
  const inspect = () => inspectMacosOpenfortivpn({
    binaryPath: policy.binaryPath,
    expectedVersion: policy.version,
    expectedFileMarker: policy.fileMarker,
  });
  let problems = inspect();

  if (problems.length > 0 && !checkOnly) {
    console.warn(`macOS Fortinet 引擎需要重建:\n- ${problems.join('\n- ')}`);
    const buildScript = path.join(repositoryRoot, 'scripts', 'build-openfortivpn-intel.sh');
    const buildResult = spawnSync('/bin/bash', [buildScript, policy.binaryPath], {
      cwd: repositoryRoot,
      stdio: 'inherit',
    });
    if (buildResult.error || buildResult.status !== 0) {
      throw new Error(`重建 macOS Fortinet 引擎失败: ${buildResult.error?.message ?? `退出码 ${buildResult.status}`}`);
    }
    problems = inspect();
  }

  if (problems.length > 0) {
    throw new Error(`macOS Fortinet 引擎校验失败:\n- ${problems.join('\n- ')}`);
  }

  console.log(`macOS Fortinet 引擎校验通过: openfortivpn ${policy.version} (${policy.suffix})`);
  return { skipped: false, policy };
};

const isDirectExecution = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectExecution) {
  try {
    prepareMacosOpenfortivpn({ checkOnly: process.argv.includes('--check') });
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
