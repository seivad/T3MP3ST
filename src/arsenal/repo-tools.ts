/**
 * Read-only repository tools for the Code Review Analyst.
 *
 * Each tool is bound to one repository root and can only read inside it: paths are resolved with
 * realpath, so neither `..` nor a symlink planted in the repository escapes. Nothing here writes,
 * executes, or reaches the network. Secret values the scanners already flagged are redacted from
 * file reads, so the model never sees (or echoes) them.
 */

import { readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { CustomTool } from '../types/index.js';
import { redactString } from '../redact.js';

export const REPO_TOOL_NAMES = ['list_files', 'read_file', 'search_code'] as const;

const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', '.next', '__pycache__', '.venv', 'venv', 'target', 'coverage']);
const MAX_FILE_BYTES = 256 * 1024;
const MAX_READ_LINES = 400;
const MAX_LIST = 500;
const MAX_MATCHES = 60;

/** The real path of `input` inside `root`, or null if it does not exist or escapes the root. */
export function containedPath(repoRoot: string, input: string): string | null {
  try {
    const root = realpathSync(repoRoot);
    const real = realpathSync(resolve(root, input.replace(/^\/+/, '')));
    const rel = relative(root, real);
    if (rel === '') return real;
    if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return null;
    return real;
  } catch {
    return null;
  }
}

/** Every regular file under `root` (relative paths), skipping dependency and build directories. */
export function walkRepo(root: string, limit = 20_000): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length > 0 && out.length < limit) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        out.push(relative(root, full));
      }
    }
  }
  return out.sort();
}

function readText(path: string): string | null {
  try {
    if (statSync(path).size > MAX_FILE_BYTES) return null;
    const buffer = readFileSync(path);
    if (buffer.includes(0)) return null; // binary
    return buffer.toString('utf8');
  } catch {
    return null;
  }
}

/** The three read-only tools, bound to `repoRoot` (an absolute, already-resolved path). */
export function createRepoTools(repoRoot: string): CustomTool[] {
  const root = realpathSync(repoRoot);
  return [
    {
      name: 'list_files',
      description: 'List files in the repository under review (optionally under a sub-directory or matching a substring).',
      category: 'code',
      riskTier: 'local_read',
      parameters: [
        { name: 'path', type: 'string', description: 'Sub-directory to list, relative to the repository root', required: false },
        { name: 'contains', type: 'string', description: 'Only list paths containing this substring', required: false },
      ],
      handler: async (context) => {
        const sub = typeof context.parameters.path === 'string' ? context.parameters.path : '';
        const base = containedPath(root, sub || '.');
        if (!base) return { success: false, error: `path not found in repository: ${sub}` };
        const filter = typeof context.parameters.contains === 'string' ? context.parameters.contains : '';
        const files = walkRepo(base).map((f) => relative(root, join(base, f))).filter((f) => !filter || f.includes(filter));
        const shown = files.slice(0, MAX_LIST);
        return {
          success: true,
          output: `${files.length} file(s)${files.length > shown.length ? `, first ${shown.length} shown` : ''}:\n${shown.join('\n')}`,
        };
      },
    },
    {
      name: 'read_file',
      description: 'Read a file from the repository under review, with line numbers. Secret values are redacted.',
      category: 'code',
      riskTier: 'local_read',
      parameters: [
        { name: 'path', type: 'string', description: 'File path relative to the repository root', required: true },
        { name: 'start_line', type: 'number', description: 'First line to show (1-based)', required: false },
        { name: 'end_line', type: 'number', description: 'Last line to show', required: false },
      ],
      handler: async (context) => {
        const input = String(context.parameters.path ?? '');
        const path = containedPath(root, input);
        if (!path) return { success: false, error: `file not found in repository: ${input}` };
        const text = readText(path);
        if (text === null) return { success: false, error: `${input} is binary or larger than ${MAX_FILE_BYTES} bytes` };
        const lines = text.split('\n');
        const start = Math.max(1, Number(context.parameters.start_line) || 1);
        const end = Math.min(lines.length, Number(context.parameters.end_line) || start + MAX_READ_LINES - 1, start + MAX_READ_LINES - 1);
        const body = lines.slice(start - 1, end).map((line, i) => `${String(start + i).padStart(5)}  ${line}`).join('\n');
        return { success: true, output: `${relative(root, path)} (lines ${start}-${end} of ${lines.length})\n${redactString(body)}` };
      },
    },
    {
      name: 'search_code',
      description: 'Search the repository for a regular expression; returns file:line matches. Secret values are redacted.',
      category: 'code',
      riskTier: 'local_read',
      parameters: [
        { name: 'pattern', type: 'string', description: 'JavaScript regular expression (case-insensitive)', required: true },
        { name: 'path_contains', type: 'string', description: 'Only search paths containing this substring', required: false },
      ],
      handler: async (context) => {
        let regex: RegExp;
        try {
          regex = new RegExp(String(context.parameters.pattern ?? ''), 'i');
        } catch (error) {
          return { success: false, error: `invalid pattern: ${error instanceof Error ? error.message : String(error)}` };
        }
        const filter = typeof context.parameters.path_contains === 'string' ? context.parameters.path_contains : '';
        const matches: string[] = [];
        for (const file of walkRepo(root)) {
          if (filter && !file.includes(filter)) continue;
          const text = readText(join(root, file));
          if (text === null) continue;
          const lines = text.split('\n');
          for (let i = 0; i < lines.length && matches.length < MAX_MATCHES; i++) {
            if (lines[i].length < 2000 && regex.test(lines[i])) {
              matches.push(`${file}:${i + 1}: ${redactString(lines[i].trim()).slice(0, 240)}`);
            }
          }
          if (matches.length >= MAX_MATCHES) break;
        }
        return { success: true, output: matches.length ? matches.join('\n') : 'no matches' };
      },
    },
  ];
}
