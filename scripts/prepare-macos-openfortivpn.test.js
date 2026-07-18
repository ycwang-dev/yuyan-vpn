import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  inspectMacosOpenfortivpn,
  prepareMacosOpenfortivpn,
  resolveMacosEnginePolicy,
} from './prepare-macos-openfortivpn.js';

/** 创建可执行的伪 openfortivpn，便于验证版本与补丁标记。 */
const createFakeEngine = ({ version = '1.24.1', markers = [] } = {}) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'yuyan-openfortivpn-check-'));
  const binaryPath = path.join(directory, 'openfortivpn');
  fs.writeFileSync(
    binaryPath,
    `#!/bin/sh\n# ${markers.join(' | ')}\nprintf '%s\\n' '${version}'\n`,
    { mode: 0o755 },
  );
  return binaryPath;
};

test('非 macOS 构建跳过 sidecar 准备', () => {
  assert.deepEqual(prepareMacosOpenfortivpn({ platform: 'linux' }), { skipped: true });
});

test('从锁文件解析 arm64 引擎版本与目标路径', () => {
  const policy = resolveMacosEnginePolicy({ architecture: 'arm64' });
  assert.equal(policy.version, '1.24.1');
  assert.equal(policy.suffix, 'aarch64-apple-darwin');
  assert.match(policy.binaryPath, /openfortivpn-aarch64-apple-darwin$/);
});

test('完整补丁标记和版本通过校验', () => {
  const markers = ['marker-a', 'marker-b'];
  const binaryPath = createFakeEngine({ markers });
  assert.deepEqual(inspectMacosOpenfortivpn({
    binaryPath,
    expectedVersion: '1.24.1',
    requiredMarkers: markers,
  }), []);
});

test('旧版本与缺失补丁标记会被同时拒绝', () => {
  const binaryPath = createFakeEngine({ version: '1.18.0', markers: ['marker-a'] });
  const problems = inspectMacosOpenfortivpn({
    binaryPath,
    expectedVersion: '1.24.1',
    requiredMarkers: ['marker-a', 'marker-b'],
  });

  assert.ok(problems.some((problem) => problem.includes('版本不匹配')));
  assert.ok(problems.some((problem) => problem.includes('缺少补丁标记: marker-b')));
});
