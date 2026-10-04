import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { otlpPayload, projectRow, runExport } from '../audit-export.js';

const row = {
  id: 'aud_123e4567-e89b-42d3-a456-426614174000',
  occurred_at: new Date('2026-10-01T00:00:00.000Z'), kind: 'mutation',
  actor_id: 'PRIVATE ACTOR', action: 'openclaw.agents.deploy', namespace_id: 'PRIVATE NAMESPACE',
  resource_kind: 'agent', resource_id: 'PRIVATE AGENT', outcome: 'success',
  details: { prompt: 'PRIVATE PROMPT' },
};

test('projection excludes details and pseudonymizes actor, namespace, and exact resource', () => {
  const secret = Buffer.alloc(32, 7);
  const first = projectRow(row, secret);
  const second = projectRow({ ...row, resource_id: 'ANOTHER AGENT' }, secret);
  assert.notEqual(first.resourceRef, second.resourceRef);
  assert.equal(first.eventId, row.id);
  assert.equal(JSON.stringify(first).includes('PRIVATE'), false);
  const payload = otlpPayload([first]);
  assert.equal(payload.resourceLogs[0].scopeLogs[0].logRecords[0].body.stringValue, 'oce.audit');
  assert.equal(JSON.stringify(payload).includes('PRIVATE'), false);
});

test('failed OTLP delivery does not advance the cursor', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'oce-audit-'));
  const databaseUrlFile = join(directory, 'database.key');
  const hmacKeyFile = join(directory, 'hmac.key');
  const cursorFile = join(directory, 'audit.cursor.json');
  await writeFile(databaseUrlFile, 'postgres://test:test@127.0.0.1/test', { mode: 0o600 });
  await writeFile(hmacKeyFile, Buffer.alloc(32, 3), { mode: 0o600 });
  let ended = false;
  const clientFactory = () => ({
    async connect() {}, async end() { ended = true; },
    async query(sql) { return typeof sql === 'string' && sql.startsWith('SELECT') ? { rows: [row] } : { rows: [] }; },
  });
  const config = { databaseUrlFile, hmacKeyFile, cursorFile, since: '2026-09-01T00:00:00.000Z',
    sink: { type: 'otlp', url: 'https://collector.example.com/v1/logs' } };
  await assert.rejects(runExport(config, {
    clientFactory, fetchImpl: async () => ({ status: 200, async json() { return { partialSuccess: { rejectedLogRecords: 1 } }; } }),
  }), /E_OTLP_PARTIAL/);
  assert.equal(ended, true);
  await assert.rejects(stat(cursorFile), /ENOENT/);
  await assert.rejects(stat(`${cursorFile}.lock`), /ENOENT/);
  const result = await runExport(config, { clientFactory,
    fetchImpl: async () => ({ status: 200, async json() { return {}; } }),
  });
  assert.equal(result.exported, 1);
  assert.equal((await stat(cursorFile)).mode & 0o777, 0o600);
  assert.equal(JSON.parse(await readFile(cursorFile, 'utf8')).id, row.id);
});
