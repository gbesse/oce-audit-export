import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from 'pg';
import { runExport } from '../audit-export.js';

const url = process.env.OCE_AUDIT_TEST_DATABASE_URL;

test('read-only PostgreSQL role exports an audit page and resumes without duplicates', { skip: !url }, async () => {
  const admin = new Client({ connectionString: url });
  await admin.connect();
  try {
    await admin.query('CREATE SCHEMA occ');
    await admin.query(`CREATE TABLE occ.audit_events (
      id text PRIMARY KEY, occurred_at timestamptz NOT NULL, kind text NOT NULL,
      actor_id text NOT NULL, action text NOT NULL, namespace_id text,
      resource_kind text NOT NULL, resource_id text NOT NULL, outcome text NOT NULL,
      details jsonb)`);
    await admin.query(`CREATE ROLE oce_audit_reader LOGIN PASSWORD 'test-reader-password'`);
    await admin.query('GRANT USAGE ON SCHEMA occ TO oce_audit_reader');
    await admin.query(`GRANT SELECT (id, occurred_at, kind, actor_id, action, namespace_id,
      resource_kind, resource_id, outcome) ON occ.audit_events TO oce_audit_reader`);
    for (let index = 1; index <= 3; index++) {
      await admin.query(`INSERT INTO occ.audit_events
        (id, occurred_at, kind, actor_id, action, namespace_id, resource_kind, resource_id, outcome, details)
        VALUES ($1, $2, 'mutation', 'PRIVATE ACTOR', 'openclaw.agents.deploy',
          'PRIVATE NAMESPACE', 'agent', $3, 'success', '{"prompt":"PRIVATE PROMPT"}')`,
      [`aud_123e4567-e89b-42d3-a456-42661417400${index}`, `2026-10-01T00:00:0${index}.000Z`, `PRIVATE AGENT ${index}`]);
    }
    const directory = await mkdtemp(join(tmpdir(), 'oce-audit-pg-'));
    const databaseUrlFile = join(directory, 'database.key');
    const hmacKeyFile = join(directory, 'hmac.key');
    const cursorFile = join(directory, 'audit.cursor.json');
    const outputFile = join(directory, 'audit.ndjson');
    const readerUrl = new URL(url);
    readerUrl.username = 'oce_audit_reader';
    readerUrl.password = 'test-reader-password';
    await writeFile(databaseUrlFile, readerUrl.toString(), { mode: 0o600 });
    await writeFile(hmacKeyFile, Buffer.alloc(32, 5), { mode: 0o600 });
    const config = { databaseUrlFile, hmacKeyFile, cursorFile, since: '2026-09-01T00:00:00.000Z',
      batchSize: 2, sink: { type: 'ndjson', outputFile } };
    const first = await runExport(config);
    assert.equal(first.exported, 3);
    const lines = (await readFile(outputFile, 'utf8')).trim().split('\n');
    assert.equal(lines.length, 3);
    assert.equal(lines.join('').includes('PRIVATE'), false);
    assert.equal((await runExport(config)).exported, 0);
    const reader = new Client({ connectionString: readerUrl.toString() });
    await reader.connect();
    try { await assert.rejects(reader.query('SELECT details FROM occ.audit_events'), /permission denied/); }
    finally { await reader.end(); }
  } finally {
    await admin.end();
  }
});
