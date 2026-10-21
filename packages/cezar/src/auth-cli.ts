import { loadWorkspaceConfig, mergeWriteWorkspaceConfig } from './workspace/config.ts';

/**
 * `cezar auth` — lockout recovery for LAN access (spec 2026-10-20-lan-basic-auth-https). Works on
 * `~/.cezar/config.json` directly, so it needs no server and no password: whoever can run it
 * already owns this machine's account.
 */

export interface AuthCommandIo {
  log: (line: string) => void;
  error: (line: string) => void;
}

const defaultIo: AuthCommandIo = {
  log: (line) => console.log(line),
  error: (line) => console.error(line),
};

const USAGE = `usage:
  cezar auth [status]   show whether LAN access is on and who can sign in
  cezar auth reset      turn LAN access off and forget its username and password`;

export async function runAuthCommand(args: string[], io: AuthCommandIo = defaultIo): Promise<number> {
  const [sub = 'status'] = args;
  if (sub === 'status') {
    const security = (await loadWorkspaceConfig()).security;
    io.log(`LAN access: ${security?.lanAccess ? 'on' : 'off'}`);
    io.log(`sign-in:    ${security?.auth ? `user "${security.auth.username}"` : 'not configured'}`);
    return 0;
  }
  if (sub === 'reset') {
    await mergeWriteWorkspaceConfig((config) => {
      delete config.security;
    });
    io.log('LAN access is off and its credentials are gone.');
    io.log('A cockpit that is already running keeps its LAN listener until it restarts —');
    io.log('restart it, or switch LAN access off in Settings → Security from this machine.');
    return 0;
  }
  io.error(USAGE);
  return sub === 'help' || sub === '--help' ? 0 : 1;
}
