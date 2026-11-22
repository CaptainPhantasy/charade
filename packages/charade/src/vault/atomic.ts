import {
  chmodSync,
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

export interface LockHandle {
  release(): void;
}

/**
 * Write a file atomically: temp file in the same directory, fsync, rename,
 * fsync the directory. No reader ever observes a partial write.
 */
export function writeAtomic(filePath: string, data: Buffer, mode = 0o600): void {
  const directory = dirname(filePath);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temp = join(
    directory,
    `.${basename(filePath)}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`,
  );
  const fd = openSync(temp, "wx", mode);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(temp, filePath);
    chmodSync(filePath, mode);
    const dirFd = openSync(directory, "r");
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
  } catch (error) {
    try {
      unlinkSync(temp);
    } catch {
      // The temp file may already have been renamed.
    }
    throw error;
  }
}

/**
 * One writer at a time. The broker is the normal holder; offline commands
 * refuse while a broker holds the lock. Stale-lock recovery is deliberate:
 * a lock is removed only when its recorded pid is no longer alive.
 */
export function acquireLock(directory: string): LockHandle {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const lockPath = join(directory, "vault.lock");
  let fd: number;
  try {
    fd = openSync(lockPath, "wx", 0o600);
  } catch (error) {
    if (isLockStale(lockPath)) {
      try {
        unlinkSync(lockPath);
      } catch {
        // Another writer may have recovered it first.
      }
      fd = openSync(lockPath, "wx", 0o600);
    } else {
      throw error;
    }
  }
  try {
    writeSync(fd, JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  let held = true;
  return {
    release(): void {
      if (!held) return;
      held = false;
      try {
        unlinkSync(lockPath);
      } catch {
        // A missing lock is already released.
      }
    },
  };
}

function isLockStale(lockPath: string): boolean {
  try {
    const record = JSON.parse(readFileSync(lockPath, "utf8")) as { pid?: unknown };
    const pid = Number(record.pid);
    if (!Number.isInteger(pid) || pid <= 0) return false;
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
}
