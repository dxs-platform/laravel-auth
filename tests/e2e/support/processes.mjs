import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

export function startConsumer(directory, port) {
  const process = spawn('php', ['artisan', 'serve', '--host=127.0.0.1', `--port=${port}`], {
    cwd: directory,
    env: { ...globalThis.process.env },
    detached: true,
    stdio: 'ignore',
  });
  process.unref();
  return {
    stop: () => {
      try { globalThis.process.kill(-process.pid, 'SIGTERM'); } catch {}
    },
  };
}

export async function waitForUrl(url, attempts = 60) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {}
    await delay(250);
  }
  throw new Error(`Timed out waiting for ${url}`);
}
