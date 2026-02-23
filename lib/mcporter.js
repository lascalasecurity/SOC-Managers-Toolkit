import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);

export async function mcporterCall({ tool, args = {}, cwd, env = {}, output = 'json', timeoutMs = 120000 }) {
  // Prefer --args <json> to avoid mcporter auto-parsing/typing surprises for
  // values that look like JSON (e.g. a string that contains "[]").
  const cmd = 'npx';
  const cmdArgs = [
    'mcporter',
    'call',
    '--config',
    'config/mcporter.json',
    tool,
    '--args',
    JSON.stringify(args),
    '--output',
    output
  ];

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
      // Drop known diagnostic prefixes.
      if (t.startsWith('[mcporter]')) return false;
      // Drop tool diagnostic tags like: [purple-mcp.search_vulnerabilities] ...
      // but keep real JSON arrays like: [{"a":1}] (second char is '{').
      if (t.startsWith('[') && /\[[A-Za-z0-9_.:-]+\]/.test(t) && /[A-Za-z_.:-]/.test(t[1] || '')) return false;
      return true;
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
      // Capture both single- and double-quoted JS string literals.
      const re = /(['"])((?:\\.|(?!\1)[\s\S])*)\1/g;
      let m;
      while ((m = re.exec(afterText))) {
        const quote = m[1];
        const body = m[2];
        // Decode JS-style escapes by round-tripping through JSON.parse.
        const decodedChunk = JSON.parse('"' + body.replace(/"/g, '\\"') + '"');
        chunks.push(decodedChunk);
        // Stop at first plausible chunk; mcporter sometimes includes multiple quoted fields after text:.
        if (chunks.length >= 1) break;
      }
      if (chunks.length) {
        const dt = chunks.join('').trim();
        const fo = dt.indexOf('{');
        const fa = dt.indexOf('[');
        const f =
          fo === -1 ? fa :
          fa === -1 ? fo :
          Math.min(fo, fa);
        return { stdout: (f >= 0 ? dt.slice(f) : dt).trim(), stderr };
      }
    } catch {
      // fall through to best-effort JSON extraction
    }
  }

  // If output begins with a diagnostic tag like "[search_vulnerabilities]" on the
  // same line as JSON, skip past the tag.
  let candidate = stripped;
  if (/^\[[A-Za-z0-9_.:-]+\]/.test(candidate)) {
    const close = candidate.indexOf(']');
    if (close >= 0) candidate = candidate.slice(close + 1).trimStart();
  }

  const firstObj = candidate.indexOf('{');
  const firstArr = candidate.indexOf('[');
  const first =
    firstObj === -1 ? firstArr :
    firstArr === -1 ? firstObj :
    Math.min(firstObj, firstArr);

  const cleanedStdout = (first >= 0 ? candidate.slice(first) : candidate).trim();

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
