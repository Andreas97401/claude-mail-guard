// Shared helpers: read the JSON Claude Code sends to a hook, answer with a decision or extra context.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export function readInput() {
  try { return JSON.parse(readFileSync(0, 'utf8')); } catch { return {}; }
}

function decide(decision, reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  }));
  process.exit(0);
}

// Block the tool call. Claude reads the reason and adapts.
export const deny = (reason) => decide('deny', reason);

// Ask the human first. In headless mode (`claude -p`, cron, CI) nobody can answer,
// so Claude Code treats it as a refusal. That is the point.
export const ask = (reason) => decide('ask', reason);

// Add text to Claude's context next to a tool result.
export function addContext(event, text) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: event, additionalContext: text },
  }));
  process.exit(0);
}

// Optional config: guard.config.json next to the hooks folder, or GUARD_CONFIG=<path>.
const DEFAULTS = {
  // Hosts a session may still reach after reading mail (reading your own inbox, signing in).
  trustedHosts: [
    'mail.google.com', 'accounts.google.com', 'calendar.google.com',
    'outlook.office.com', 'outlook.office365.com', 'outlook.live.com', 'outlook.cloud.microsoft',
    'login.microsoftonline.com', 'localhost', '127.0.0.1',
  ],
  // Your own servers: ssh/scp/rsync to them is not an exfiltration channel.
  trustedSshHosts: [],
  // Local commands that print mail content (regex sources). They mark the session.
  mailCommands: [],
  // Files written from mail (digests, drafted replies). Reading them marks the session too.
  mailFiles: [],
};

export function loadConfig() {
  const here = dirname(fileURLToPath(import.meta.url));
  const file = process.env.GUARD_CONFIG || join(here, '..', 'guard.config.json');
  let user = {};
  try { user = JSON.parse(readFileSync(file, 'utf8')); } catch {}
  return { ...DEFAULTS, ...user };
}

export const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
