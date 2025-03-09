/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('users', (table) => {
      table.increments('id').primary();
      table.string('username').unique().notNullable();
      table.string('email').unique().notNullable();
      table.string('password_hash').notNullable();
      table.string('role').defaultTo('user');
      table.boolean('is_email_verified').defaultTo(false);
      table.timestamps(true, true);
    });
  };
  
  exports.down = function(knex) {
    return knex.schema.dropTable('users');
  };
