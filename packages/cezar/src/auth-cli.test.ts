import { describe, expect, it } from 'vitest';
import { runAuthCommand } from './auth-cli.ts';
import { loadWorkspaceConfig, mergeWriteWorkspaceConfig } from './workspace/config.ts';

describe('cezar auth (spec 2026-10-20-lan-basic-auth-https)', () => {
  const io = () => {
    const lines: string[] = [];
    return { lines, io: { log: (line: string) => lines.push(line), error: (line: string) => lines.push(line) } };
  };

  it('reset turns LAN access off and forgets the credentials, leaving the rest of the config', async () => {
    await mergeWriteWorkspaceConfig((config) => {
      config.security = { lanAccess: true, auth: { username: 'alex', salt: 'ab', hash: 'cd' } };
      config.modelsLocked = true;
    });
    const status = io();
    expect(await runAuthCommand([], status.io)).toBe(0);
    expect(status.lines.join('\n')).toContain('LAN access: on');
    expect(status.lines.join('\n')).toContain('user "alex"');

    expect(await runAuthCommand(['reset'], io().io)).toBe(0);
    const config = await loadWorkspaceConfig();
    expect(config.security).toBeUndefined();
    expect(config.modelsLocked).toBe(true);
  });

  it('rejects an unknown subcommand with the usage', async () => {
    const out = io();
    expect(await runAuthCommand(['nope'], out.io)).toBe(1);
    expect(out.lines.join('\n')).toContain('cezar auth reset');
  });
});
