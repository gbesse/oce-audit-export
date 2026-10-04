#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { initKey, runExport } from './audit-export.js';

if (process.argv.includes('--help')) {
  process.stdout.write('Utilisation / Usage / Uso: node cli.js init-key file | run config.json\n');
  process.exit(0);
}
try {
  if (process.argv[2] === 'init-key') {
    await initKey(resolve(process.argv[3]));
    process.stdout.write('Clé créée / Key created / Clave creada\n');
  } else if (process.argv[2] === 'run') {
    const path = resolve(process.argv[3]);
    const config = JSON.parse(await readFile(path, 'utf8'));
    const base = dirname(path);
    for (const name of ['databaseUrlFile', 'hmacKeyFile', 'cursorFile']) {
      if (typeof config[name] === 'string' && !config[name].startsWith('/')) config[name] = resolve(base, config[name]);
    }
    if (config.sink?.type === 'ndjson' && !config.sink.outputFile.startsWith('/')) config.sink.outputFile = resolve(base, config.sink.outputFile);
    if (config.sink?.headersFile && !config.sink.headersFile.startsWith('/')) config.sink.headersFile = resolve(base, config.sink.headersFile);
    const report = await runExport(config);
    process.stdout.write(`${JSON.stringify(report)}\n`);
    process.exitCode = report.status === 'complete' ? 0 : 2;
  } else throw new Error('E_MODE');
} catch (error) {
  process.stderr.write(`oce-audit-export:${error.message?.startsWith('E_') ? error.message : 'E_RUN_FAILED'}\n`);
  process.exitCode = 1;
}
