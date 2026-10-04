import { createHmac, randomBytes } from 'node:crypto';
import { open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Client } from 'pg';

const safeCode = /^[a-z0-9_.:-]{1,128}$/i;
const safeId = /^aud_[a-f0-9-]{36}$/;
const safeTimestamp = (value) => {
  const time = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(time.getTime())) throw new Error('E_TIMESTAMP');
  return time.toISOString();
};

async function privateFile(path) {
  const info = await stat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0) throw new Error('E_PRIVATE_FILE');
  return readFile(path);
}

export async function initKey(path) {
  await writeFile(path, randomBytes(32), { flag: 'wx', mode: 0o600 });
}

export function validateConfig(input) {
  if (!input || typeof input !== 'object' || !input.databaseUrlFile || !input.hmacKeyFile || !input.cursorFile || !input.since || !input.sink) throw new Error('E_CONFIG');
  if (!Number.isFinite(Date.parse(input.since))) throw new Error('E_SINCE');
  const batchSize = input.batchSize ?? 100;
  const maxBatches = input.maxBatches ?? 100;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 500 || !Number.isInteger(maxBatches) || maxBatches < 1 || maxBatches > 10000) throw new Error('E_LIMIT');
  const sink = input.sink;
  if (sink.type === 'ndjson') {
    if (typeof sink.outputFile !== 'string' || !sink.outputFile) throw new Error('E_SINK');
  } else if (sink.type === 'otlp') {
    const url = new URL(sink.url);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new Error('E_HTTPS_REQUIRED');
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/v1/logs') throw new Error('E_OTLP_URL');
  } else throw new Error('E_SINK');
  return { ...input, batchSize, maxBatches };
}

export function projectRow(row, secret) {
  const id = row.id;
  if (typeof id !== 'string' || !safeId.test(id)) throw new Error('E_EVENT_ID');
  const ref = (...parts) => createHmac('sha256', secret).update(JSON.stringify(parts)).digest('hex');
  const code = (value) => typeof value === 'string' && safeCode.test(value) ? value : 'unknown';
  return {
    schema: 'oce-audit-export.v1', eventId: id, occurredAt: safeTimestamp(row.occurred_at),
    kind: code(row.kind), action: code(row.action), outcome: code(row.outcome),
    actorRef: ref('actor', row.actor_id),
    namespaceRef: row.namespace_id == null ? null : ref('namespace', row.namespace_id),
    resourceKind: code(row.resource_kind),
    resourceRef: ref('resource', row.resource_kind, row.resource_id),
  };
}

function attr(key, value) { return { key, value: { stringValue: String(value) } }; }
export function otlpPayload(events) {
  return { resourceLogs: [{
    resource: { attributes: [attr('service.name', 'oce-audit-export')] },
    scopeLogs: [{ scope: { name: 'oce-audit-export' }, logRecords: events.map((event) => ({
      timeUnixNano: (BigInt(Date.parse(event.occurredAt)) * 1000000n).toString(),
      severityNumber: 9, severityText: 'INFO', body: { stringValue: 'oce.audit' },
      attributes: Object.entries(event).filter(([key]) => key !== 'occurredAt').map(([key, value]) => attr(key, value ?? '')),
    })) }],
  }] };
}

async function readCursor(path, since) {
  try {
    const data = JSON.parse((await privateFile(path)).toString('utf8'));
    if (!data || !Number.isFinite(Date.parse(data.occurredAt)) || typeof data.id !== 'string' || (data.id && !safeId.test(data.id))) throw new Error('E_CURSOR');
    return data;
  } catch (error) {
    if (error.code === 'ENOENT') return { occurredAt: safeTimestamp(since), id: '' };
    throw error;
  }
}

async function saveCursor(path, cursor) {
  const temporary = join(dirname(path), `.cursor-${randomBytes(12).toString('hex')}`);
  try {
    await writeFile(temporary, `${JSON.stringify(cursor)}\n`, { flag: 'wx', mode: 0o600 });
    await rename(temporary, path);
  } finally { await unlink(temporary).catch(() => {}); }
}

async function sendNdjson(path, events) {
  const file = await open(path, 'a', 0o600);
  try {
    const info = await file.stat();
    if (!info.isFile() || (info.mode & 0o077) !== 0) throw new Error('E_OUTPUT_PERMISSIONS');
    await file.writeFile(events.map((event) => JSON.stringify(event)).join('\n') + '\n');
    await file.sync();
  } finally { await file.close(); }
}

async function readOtlpHeaders(path) {
  if (!path) return {};
  const headers = JSON.parse((await privateFile(path)).toString('utf8'));
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) throw new Error('E_OTLP_HEADERS');
  for (const [name, value] of Object.entries(headers)) {
    if (!/^[A-Za-z0-9-]{1,64}$/.test(name) || typeof value !== 'string' || !/^[\x20-\x7e]{1,4096}$/.test(value)) throw new Error('E_OTLP_HEADERS');
  }
  return headers;
}

async function sendOtlp(sink, events, fetchImpl) {
  const headers = await readOtlpHeaders(sink.headersFile);
  const response = await fetchImpl(sink.url, {
    method: 'POST', headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify(otlpPayload(events)), signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 200) throw new Error('E_OTLP_RESPONSE');
  const result = await response.json();
  if (Number(result?.partialSuccess?.rejectedLogRecords ?? 0) > 0) throw new Error('E_OTLP_PARTIAL');
}

const query = `SELECT id, occurred_at, kind, actor_id, action, namespace_id, resource_kind, resource_id, outcome
FROM occ.audit_events
WHERE (occurred_at, id) > ($1::timestamptz, $2::text)
ORDER BY occurred_at, id
LIMIT $3`;

export async function runExport(input, { fetchImpl = fetch, clientFactory = (url) => new Client({ connectionString: url, application_name: 'oce-audit-export' }) } = {}) {
  const config = validateConfig(input);
  const [databaseUrlBytes, secret] = await Promise.all([privateFile(config.databaseUrlFile), privateFile(config.hmacKeyFile)]);
  const databaseUrl = databaseUrlBytes.toString('utf8').trim();
  if (!databaseUrl.startsWith('postgres://') && !databaseUrl.startsWith('postgresql://')) throw new Error('E_DATABASE_URL');
  if (secret.length !== 32) throw new Error('E_HMAC_KEY');
  const lockPath = `${config.cursorFile}.lock`;
  let lock;
  try { lock = await open(lockPath, 'wx', 0o600); }
  catch (error) { if (error.code === 'EEXIST') throw new Error('E_LOCKED'); throw error; }
  const client = clientFactory(databaseUrl);
  let connected = false;
  let exported = 0;
  let batches = 0;
  try {
    let cursor = await readCursor(config.cursorFile, config.since);
    await client.connect();
    connected = true;
    for (; batches < config.maxBatches; batches++) {
      await client.query('BEGIN READ ONLY');
      let result;
      try {
        result = await client.query(query, [cursor.occurredAt, cursor.id, config.batchSize]);
        await client.query('COMMIT');
      } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
      if (!result.rows.length) return { schema: 'oce-audit-export-report.v1', status: 'complete', exported, batches };
      const events = result.rows.map((row) => projectRow(row, secret));
      if (config.sink.type === 'ndjson') await sendNdjson(config.sink.outputFile, events);
      else await sendOtlp(config.sink, events, fetchImpl);
      const last = result.rows.at(-1);
      cursor = { occurredAt: safeTimestamp(last.occurred_at), id: last.id };
      await saveCursor(config.cursorFile, cursor);
      exported += events.length;
      if (result.rows.length < config.batchSize) return { schema: 'oce-audit-export-report.v1', status: 'complete', exported, batches: batches + 1 };
    }
    return { schema: 'oce-audit-export-report.v1', status: 'limit', exported, batches };
  } finally {
    if (connected) await client.end().catch(() => {});
    await lock.close();
    await unlink(lockPath).catch(() => {});
  }
}
