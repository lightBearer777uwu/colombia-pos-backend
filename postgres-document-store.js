const { Pool } = require('pg');
const fs = require('node:fs');
const path = require('node:path');

const TIMESTAMP_KEY = '__tiendaTimestamp';
const FIELD_OPERATION_KEY = '__tiendaFieldOperation';

class StoreError extends Error {
  constructor(message, status = 500, code) {
    super(message);
    this.name = 'StoreError';
    this.status = status;
    this.code = code;
  }
}

class StoreTimestamp {
  constructor(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) {
      throw new TypeError('A valid timestamp date is required.');
    }
    this.date = date;
    this.seconds = Math.floor(date.getTime() / 1000);
    this.nanoseconds = (date.getTime() % 1000) * 1000000;
  }

  static fromDate(date) {
    return new StoreTimestamp(date);
  }

  toDate() {
    return new Date(this.date);
  }

  toMillis() {
    return this.date.getTime();
  }

  valueOf() {
    return this.toMillis();
  }

  toJSON() {
    return { _seconds: this.seconds, _nanoseconds: this.nanoseconds };
  }
}

const FieldValue = Object.freeze({
  serverTimestamp: () => ({ [FIELD_OPERATION_KEY]: 'serverTimestamp' }),
  delete: () => ({ [FIELD_OPERATION_KEY]: 'delete' }),
  increment: (amount) => {
    if (!Number.isFinite(amount)) {
      throw new TypeError('A finite increment amount is required.');
    }
    return { [FIELD_OPERATION_KEY]: 'increment', amount };
  },
});

function isFieldOperation(value) {
  return value !== null &&
    typeof value === 'object' &&
    typeof value[FIELD_OPERATION_KEY] === 'string';
}

function encodeValue(value) {
  if (value instanceof StoreTimestamp) {
    return { [TIMESTAMP_KEY]: value.date.toISOString() };
  }
  if (value instanceof Date) {
    return { [TIMESTAMP_KEY]: value.toISOString() };
  }
  if (Array.isArray(value)) {
    return value.map(encodeValue);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, encodeValue(child)]),
    );
  }
  return value;
}

function decodeValue(value) {
  if (Array.isArray(value)) {
    return value.map(decodeValue);
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 1 && typeof value[TIMESTAMP_KEY] === 'string') {
      return new StoreTimestamp(value[TIMESTAMP_KEY]);
    }
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, decodeValue(child)]),
    );
  }
  return value;
}

function resolveValue(value, previousValue, deleting = false) {
  if (isFieldOperation(value)) {
    switch (value[FIELD_OPERATION_KEY]) {
      case 'serverTimestamp':
        return new StoreTimestamp(new Date());
      case 'delete':
        return deleting ? undefined : previousValue;
      case 'increment':
        return (typeof previousValue === 'number' ? previousValue : 0) +
          value.amount;
      default:
        throw new StoreError('Unsupported field operation.');
    }
  }
  if (Array.isArray(value)) {
    return value.map((child, index) =>
      resolveValue(child, previousValue?.[index]),
    );
  }
  if (value && typeof value === 'object' &&
      !(value instanceof Date) && !(value instanceof StoreTimestamp)) {
    return Object.fromEntries(
      Object.entries(value)
        .map(([key, child]) => [
          key,
          resolveValue(child, previousValue?.[key], true),
        ])
        .filter(([, child]) => child !== undefined),
    );
  }
  return value;
}

function mergeValues(existing, patch) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch) ||
      patch instanceof Date || patch instanceof StoreTimestamp ||
      isFieldOperation(patch)) {
    return resolveValue(patch, existing);
  }
  const result = existing && typeof existing === 'object' &&
      !Array.isArray(existing)
    ? { ...existing }
    : {};
  for (const [key, value] of Object.entries(patch)) {
    if (isFieldOperation(value) && value[FIELD_OPERATION_KEY] === 'delete') {
      delete result[key];
    } else if (value && typeof value === 'object' && !Array.isArray(value) &&
        !(value instanceof Date) && !(value instanceof StoreTimestamp) &&
        !isFieldOperation(value)) {
      result[key] = mergeValues(result[key], value);
    } else {
      result[key] = resolveValue(value, result[key]);
    }
  }
  return result;
}

function setAtPath(target, path, value) {
  const segments = path.split('.');
  let current = target;
  for (const segment of segments.slice(0, -1)) {
    if (!current[segment] || typeof current[segment] !== 'object' ||
        Array.isArray(current[segment])) {
      current[segment] = {};
    }
    current = current[segment];
  }
  const key = segments[segments.length - 1];
  if (isFieldOperation(value) && value[FIELD_OPERATION_KEY] === 'delete') {
    delete current[key];
  } else {
    current[key] = resolveValue(value, current[key]);
  }
}

class DocumentSnapshot {
  constructor(id, value, reference = null) {
    this.id = id;
    this.exists = value !== undefined;
    this._value = value;
    this.ref = reference;
  }

  data() {
    return this.exists ? decodeValue(this._value) : undefined;
  }
}

class QuerySnapshot {
  constructor(docs) {
    this.docs = docs;
    this.size = docs.length;
    this.empty = docs.length === 0;
  }
}

class DocumentReference {
  constructor(store, path, client) {
    this.store = store;
    this.path = path;
    this.id = path.split('/').pop();
    this.client = client;
  }

  collection(name) {
    return new CollectionReference(this.store, `${this.path}/${name}`, this.client);
  }

  async get() {
    return this.store.getDocument(this, this.client);
  }

  async set(value, options = {}) {
    return this.store.setDocument(this, value, options, this.client);
  }

  async create(value) {
    return this.store.createDocument(this, value, this.client);
  }

  async update(value) {
    return this.store.updateDocument(this, value, this.client);
  }

  async delete() {
    return this.store.deleteDocument(this, this.client);
  }
}

class Query {
  constructor(store, path, filters = [], ordering = null, maxResults = null, client = null) {
    this.store = store;
    this.path = path;
    this.filters = filters;
    this.ordering = ordering;
    this.maxResults = maxResults;
    this.client = client;
  }

  where(field, operator, value) {
    if (!['==', '<=', '>='].includes(operator)) {
      throw new StoreError(`Unsupported query operator: ${operator}`);
    }
    return new Query(
      this.store,
      this.path,
      [...this.filters, { field, operator, value }],
      this.ordering,
      this.maxResults,
      this.client,
    );
  }

  orderBy(field, direction = 'asc') {
    if (!['asc', 'desc'].includes(direction)) {
      throw new StoreError(`Unsupported sort direction: ${direction}`);
    }
    return new Query(
      this.store,
      this.path,
      this.filters,
      { field, direction },
      this.maxResults,
      this.client,
    );
  }

  limit(amount) {
    if (!Number.isSafeInteger(amount) || amount < 0) {
      throw new StoreError('A non-negative query limit is required.');
    }
    return new Query(
      this.store,
      this.path,
      this.filters,
      this.ordering,
      amount,
      this.client,
    );
  }

  async get() {
    return this.store.getCollection(this);
  }
}

class CollectionReference extends Query {
  doc(id) {
    id ??= require('node:crypto').randomUUID();
    if (typeof id !== 'string' || id.length === 0 || id.includes('/')) {
      throw new StoreError('A valid document identifier is required.');
    }
    return new DocumentReference(this.store, `${this.path}/${id}`, this.client);
  }

  async add(value) {
    const id = require('node:crypto').randomUUID();
    const reference = this.doc(id);
    await reference.create(value);
    return reference;
  }
}

class WriteBatch {
  constructor(store) {
    this.store = store;
    this.operations = [];
  }

  set(reference, value, options = {}) {
    this.operations.push((transaction) =>
      transaction.set(reference, value, options));
    return this;
  }

  async commit() {
    await this.store.runTransaction(async (transaction) => {
      for (const operation of this.operations) {
        await operation(transaction);
      }
    });
  }
}

class Transaction {
  constructor(store, client) {
    this.store = store;
    this.client = client;
  }

  get(reference) {
    if (reference instanceof Query) {
      return this.store.getCollection(reference, this.client);
    }
    return this.store.getDocument(reference, this.client);
  }

  set(reference, value, options = {}) {
    return this.store.setDocument(reference, value, options, this.client);
  }

  create(reference, value) {
    return this.store.createDocument(reference, value, this.client);
  }

  update(reference, value) {
    return this.store.updateDocument(reference, value, this.client);
  }

  delete(reference) {
    return this.store.deleteDocument(reference, this.client);
  }
}

class PostgresDocumentStore {
  constructor() {
    this._poolInstance = null;
    this.schemaReady = null;
  }

  pool() {
    return this._pool();
  }

  _pool() {
    if (!process.env.DATABASE_URL) {
      throw new StoreError('The PostgreSQL DATABASE_URL is not configured.', 503);
    }
    if (!this._poolInstance) {
      this._poolInstance = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.DATABASE_SSL === 'require'
          ? { rejectUnauthorized: true }
          : undefined,
        max: Number.parseInt(process.env.DATABASE_POOL_SIZE || '10', 10),
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000,
      });
    }
    return this._poolInstance;
  }

  async _ready() {
    if (!this.schemaReady) {
      const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
      this.schemaReady = this._pool().query(schema).catch((error) => {
        this.schemaReady = null;
        throw error;
      });
    }
    return this.schemaReady;
  }

  collection(path) {
    return new CollectionReference(this, path);
  }

  async initialize() {
    await this._ready();
  }

  batch() {
    return new WriteBatch(this);
  }

  async runTransaction(callback) {
    await this._ready();
    const client = await this._pool().connect();
    try {
      await client.query('BEGIN');
      await client.query('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');
      const result = await callback(new Transaction(this, client));
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      if (error.code === '23505') {
        throw new StoreError('A record with that identifier already exists.', 409, error.code);
      }
      if (error.code === '40001' || error.code === '40P01') {
        throw new StoreError('The record changed concurrently. Please retry.', 409, error.code);
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async getDocument(reference, client) {
    await this._ready();
    const result = await this._query(
      'SELECT data FROM business_documents WHERE path = $1',
      [reference.path],
      client,
    );
    return new DocumentSnapshot(
      reference.id,
      result.rowCount ? result.rows[0].data : undefined,
      reference,
    );
  }

  async setDocument(reference, value, options, client) {
    await this._ready();
    if (options.merge && !client) {
      return this.runTransaction((transaction) =>
        transaction.set(reference, value, options));
    }
    const existing = options.merge
      ? await this.getDocument(reference, client)
      : null;
    const data = existing?.exists
      ? mergeValues(existing.data(), value)
      : resolveValue(value, undefined, true);
    return this._upsert(reference, data, client);
  }

  async createDocument(reference, value, client) {
    await this._ready();
    const data = resolveValue(value, undefined, true);
    const { collectionPath, id } = this._documentLocation(reference.path);
    try {
      await this._query(
        `INSERT INTO business_documents (path, collection_path, document_id, data)
         VALUES ($1, $2, $3, $4::jsonb)`,
        [reference.path, collectionPath, id, JSON.stringify(encodeValue(data))],
        client,
      );
    } catch (error) {
      if (error.code === '23505') {
        throw new StoreError('A record with that identifier already exists.', 409, error.code);
      }
      throw error;
    }
  }

  async updateDocument(reference, patch, client) {
    await this._ready();
    if (!client) {
      return this.runTransaction((transaction) =>
        transaction.update(reference, patch));
    }
    const current = await this.getDocument(reference, client);
    if (!current.exists) {
      throw new StoreError('The record to update does not exist.', 404);
    }
    const data = { ...current.data() };
    for (const [field, value] of Object.entries(patch)) {
      setAtPath(data, field, value);
    }
    return this._upsert(reference, data, client);
  }

  async deleteDocument(reference, client) {
    await this._ready();
    await this._query(
      'DELETE FROM business_documents WHERE path = $1',
      [reference.path],
      client,
    );
  }

  async getCollection(query, client) {
    await this._ready();
    const params = [query.path];
    const predicates = ['collection_path = $1'];
    for (const filter of query.filters) {
      const field = filter.field.split('.');
      const fieldParameter = params.push(field);
      const expression = `CASE
        WHEN jsonb_typeof(data #> $${fieldParameter}::text[]) = 'object'
          AND (data #> $${fieldParameter}::text[]) ? '${TIMESTAMP_KEY}'
        THEN data #>> ($${fieldParameter}::text[] || ARRAY['${TIMESTAMP_KEY}'])
        ELSE data #>> $${fieldParameter}::text[]
      END`;
      if (filter.value === null) {
        predicates.push(`(data #> $${fieldParameter}::text[]) ${filter.operator === '==' ? 'IS' : 'IS NOT'} NULL`);
        continue;
      }
      const value = params.push(queryValue(filter.value));
      const operator = filter.operator === '==' ? '=' : filter.operator;
      predicates.push(`${expression} ${operator} $${value}`);
    }
    let orderSql = 'document_id ASC';
    if (query.ordering) {
      const field = params.push(query.ordering.field.split('.'));
      orderSql = `CASE
        WHEN jsonb_typeof(data #> $${field}::text[]) = 'object'
          AND (data #> $${field}::text[]) ? '${TIMESTAMP_KEY}'
        THEN data #>> ($${field}::text[] || ARRAY['${TIMESTAMP_KEY}'])
        ELSE data #>> $${field}::text[]
      END ${query.ordering.direction.toUpperCase()} NULLS LAST, document_id ASC`;
    }
    let sql = `SELECT document_id, data FROM business_documents
      WHERE ${predicates.join(' AND ')}
      ORDER BY ${orderSql}`;
    if (query.maxResults !== null) {
      const limit = params.push(query.maxResults);
      sql += ` LIMIT $${limit}`;
    }
    const result = await this._query(sql, params, client);
    return new QuerySnapshot(
      result.rows.map((row) => new DocumentSnapshot(
        row.document_id,
        row.data,
        new DocumentReference(
          this,
          `${query.path}/${row.document_id}`,
          client,
        ),
      )),
    );
  }

  async _upsert(reference, data, client) {
    const { collectionPath, id } = this._documentLocation(reference.path);
    await this._query(
      `INSERT INTO business_documents (path, collection_path, document_id, data)
       VALUES ($1, $2, $3, $4::jsonb)
       ON CONFLICT (path) DO UPDATE SET
         data = EXCLUDED.data,
         updated_at = NOW()`,
      [reference.path, collectionPath, id, JSON.stringify(encodeValue(data))],
      client,
    );
  }

  _documentLocation(path) {
    const lastSeparator = path.lastIndexOf('/');
    return {
      collectionPath: path.slice(0, lastSeparator),
      id: path.slice(lastSeparator + 1),
    };
  }

  async _query(sql, params, client) {
    return (client || this._pool()).query(sql, params);
  }
}

function queryValue(value) {
  if (value instanceof StoreTimestamp) return value.date.toISOString();
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

const store = new PostgresDocumentStore();

module.exports = {
  FieldValue,
  PostgresDocumentStore,
  StoreError,
  StoreTimestamp,
  Timestamp: StoreTimestamp,
  decodeValue,
  encodeValue,
  mergeValues,
  resolveValue,
  store,
};
