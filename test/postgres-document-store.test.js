const assert = require('node:assert/strict');
const test = require('node:test');

const {
  FieldValue,
  PostgresDocumentStore,
  StoreError,
  StoreTimestamp,
  decodeValue,
  encodeValue,
  mergeValues,
  resolveValue,
} = require('../postgres-document-store');

test('round-trips timestamps through the PostgreSQL JSON representation', () => {
  const source = {
    createdAt: StoreTimestamp.fromDate(new Date('2026-01-02T03:04:05.000Z')),
    nested: { count: 2 },
  };
  const decoded = decodeValue(JSON.parse(JSON.stringify(encodeValue(source))));
  assert.ok(decoded.createdAt instanceof StoreTimestamp);
  assert.equal(decoded.createdAt.toDate().toISOString(), '2026-01-02T03:04:05.000Z');
  assert.deepEqual(decoded.nested, { count: 2 });
});

test('applies server timestamps, increments, and nested deletions', () => {
  const timestamped = resolveValue({
    createdAt: FieldValue.serverTimestamp(),
    count: FieldValue.increment(2),
  });
  assert.ok(timestamped.createdAt instanceof StoreTimestamp);
  assert.equal(timestamped.count, 2);

  const merged = mergeValues(
    { settings: { keep: true, remove: true }, count: 3 },
    {
      settings: { remove: FieldValue.delete(), added: 'yes' },
      count: FieldValue.increment(4),
    },
  );
  assert.deepEqual(merged, {
    settings: { keep: true, added: 'yes' },
    count: 7,
  });
});

test('rejects unsupported query operators before reaching the database', () => {
  const database = new PostgresDocumentStore();
  assert.throws(
    () => database.collection('businesses').where('active', '!=', true),
    StoreError,
  );
});

test('exposes the configured PostgreSQL pool to backend services', () => {
  const previousUrl = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  try {
    assert.throws(
      () => new PostgresDocumentStore().pool(),
      /DATABASE_URL is not configured/,
    );
  } finally {
    if (previousUrl !== undefined) process.env.DATABASE_URL = previousUrl;
  }
});
