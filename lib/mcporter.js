import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);

export async function mcporterCall({ tool, args = {}, cwd, env = {}, output = 'json', timeoutMs = 120000 }) {
  // mcporter expects args as key=value tokens
  const kv = [];
  for (const [k, v] of Object.entries(args)) {
    kv.push(`${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`);
  }

  const cmd = 'npx';
  const cmdArgs = ['mcporter', 'call', '--config', 'config/mcporter.json', tool, ...kv, '--output', output];

  const { stdout, stderr } = await execFileP(cmd, cmdArgs, {
    cwd,
    env: { ...process.env, ...env },
    timeout: timeoutMs,
    maxBuffer: 20 * 1024 * 1024
  });

  // mcporter may print diagnostic lines to stdout even when --output json is requested.
  // Make stdout robust for downstream JSON.parse by:
  // 1) stripping known diagnostic prefixes
  // 2) extracting the JSON payload starting at the first "{" or "[" (best-effort)
  // 3) handling mcporter "raw" formatter which is a JS object literal with a text field
  //    that contains the actual JSON as concatenated JS string chunks.
  const stripped = stdout
    .split('\n')
    .filter((line) => {
      const t = line.trimStart();
      return !t.startsWith('[mcporter]');
    })
    .join('\n')
    .trim();

  // If mcporter printed a JS object literal like:
  // { content: [ { type: 'text', text: '{\n' + '  "edges": ...' } ], isError: false }
  // extract & decode the concatenated string chunks after `text:`.
  if (stripped.includes('content:') && stripped.includes("type: 'text'") && stripped.includes('text:')) {
    try {
      const afterText = stripped.split('text:')[1] ?? '';
      const chunks = [];
      const re = /'((?:\\'|[^'])*)'/g;
      let m;
      while ((m = re.exec(afterText))) chunks.push(m[1]);
      if (chunks.length) {
        const joined = chunks.join('');
        // Decode JS-style escapes (\n, \t, \uXXXX, etc.) via JSON.parse on a quoted string.
        const decoded = JSON.parse('"' + joined.replace(/"/g, '\\"') + '"');
        return { stdout: decoded.trim(), stderr };
      }
    } catch {
      // fall through to best-effort JSON extraction
    }
  }

  const firstObj = stripped.indexOf('{');
  const firstArr = stripped.indexOf('[');
  const first =
    firstObj === -1 ? firstArr :
    firstArr === -1 ? firstObj :
    Math.min(firstObj, firstArr);

  const cleanedStdout = (first >= 0 ? stripped.slice(first) : stripped).trim();

  return { stdout: cleanedStdout, stderr };
}

export async function mcporterList({ cwd, env = {}, timeoutMs = 120000 }) {
  const cmd = 'npx';
  const cmdArgs = ['mcporter', 'list', '--config', 'config/mcporter.json'];
  const { stdout, stderr } = await execFileP(cmd, cmdArgs, {
    cwd,
    env: { ...process.env, ...env },
    timeout: timeoutMs,
    maxBuffer: 5 * 1024 * 1024
  });
  return { stdout, stderr };
}
