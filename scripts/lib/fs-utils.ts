/** Filesystem helpers shared by the cert scripts. All writes are atomic. */
import { mkdir, rename, unlink, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';

/** Create `path` and any missing parents. */
export async function ensureDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
}

/**
 * Write `data` to `path` atomically: the bytes land in a sibling temp file
 * first and are then renamed into place, so a crash never leaves a partial
 * cert or key. `mode` is applied at creation; on Windows it is ignored.
 */
export async function writeFileAtomic(
  path: string,
  data: string | Buffer,
  mode: number = 0o644,
): Promise<void> {
  await ensureDir(dirname(path));
  const tmp = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
  try {
    await writeFile(tmp, data, { mode });
    await rename(tmp, path);
  } catch (err) {
    await unlink(tmp).catch(() => undefined);
    throw err;
  }
}
