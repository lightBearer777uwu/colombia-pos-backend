require('dotenv').config();

const { store } = require('./postgres-document-store');

store.initialize()
  .then(async () => {
    await store.pool().end();
    console.log('PostgreSQL schema is ready.');
  })
  .catch((error) => {
    console.error('PostgreSQL schema migration failed:', error);
    process.exitCode = 1;
  });
