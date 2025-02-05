exports.up = function(knex) {
    return knex.schema.createTable('books', (table) => {
      table.increments('id').primary();
      table.string('title').notNullable();
      table.string('author').notNullable();
      table.date('publication_date').notNullable();
      table.string('genre').notNullable();
      table.integer('page_count').notNullable();
      table.timestamps(true, true);
    });
  };
  
  exports.down = function(knex) {
    return knex.schema.dropTable('books');
  };