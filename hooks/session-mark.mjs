// Per-session memory of "this session has read mail". Hooks are stateless processes, so the mark is
// a small file per session_id in ~/.local/state/claude-mail-read/ (MAIL_READ_DIR overrides it).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DIR = process.env.MAIL_READ_DIR || path.join(os.homedir(), '.local/state/claude-mail-read');
const file = (sid) => path.join(DIR, String(sid || 'no-session').replace(/[^\w-]/g, '_') + '.json');

export function readMark(sid) {
  try { return JSON.parse(fs.readFileSync(file(sid), 'utf8')); } catch { return null; }
}

export function setMark(sid, source, signals = []) {
  try {
    fs.mkdirSync(DIR, { recursive: true });
    const mark = readMark(sid) || { since: new Date().toISOString(), sources: [], signals: [] };
    if (!mark.sources.includes(source)) mark.sources.push(source);
    mark.signals = [...new Set([...(mark.signals || []), ...signals])];
    fs.writeFileSync(file(sid), JSON.stringify(mark));
    // Housekeeping: marks older than 7 days are useless.
    for (const f of fs.readdirSync(DIR)) {
      const p = path.join(DIR, f);
      if (Date.now() - fs.statSync(p).mtimeMs > 7 * 864e5) fs.rmSync(p, { force: true });
    }
  } catch {}
}
