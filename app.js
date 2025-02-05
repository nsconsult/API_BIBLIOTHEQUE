const express = require('express');
const knex = require('knex')(require('./knexfile').development);
const app = express();

app.use(express.json());

// Conversion des clés snake_case vers camelCase
function toCamelCase(book) {
  return {
    id: book.id,
    title: book.title,
    author: book.author,
    publicationDate: book.publication_date,
    genre: book.genre,
    pageCount: book.page_count,
    createdAt: book.created_at,
    updatedAt: book.updated_at,
  };
}

// Middleware de validation
function validateBook(req, res, next) {
  const book = req.body;
  const requiredFields = ['title', 'author', 'publicationDate', 'genre', 'pageCount'];
  
  for (const field of requiredFields) {
    if (!(field in book)) {
      return res.status(400).json({ error: `Champ requis manquant : ${field}` });
    }
  }

  if (typeof book.title !== 'string' || book.title.trim() === '') {
    return res.status(400).json({ error: 'Le titre doit être une chaîne non vide' });
  }

  if (typeof book.author !== 'string' || book.author.trim() === '') {
    return res.status(400).json({ error: "L'auteur doit être une chaîne non vide" });
  }

  if (!Date.parse(book.publicationDate)) {
    return res.status(400).json({ error: 'Date de publication invalide' });
  }

  if (typeof book.genre !== 'string' || book.genre.trim() === '') {
    return res.status(400).json({ error: 'Le genre doit être une chaîne non vide' });
  }

  if (typeof book.pageCount !== 'number' || book.pageCount <= 0) {
    return res.status(400).json({ error: 'Le nombre de pages doit être un entier positif' });
  }

  next();
}

// Routes
app.get('/books', async (req, res) => {
  try {
    const books = await knex('books').select('*');
    res.json(books.map(toCamelCase));
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des livres' });
  }
});

app.get('/books/:id', async (req, res) => {
  try {
    const book = await knex('books').where({ id: req.params.id }).first();
    book ? res.json(toCamelCase(book)) : res.status(404).json({ error: 'Livre non trouvé' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération du livre' });
  }
});

app.post('/books', validateBook, async (req, res) => {
  try {
    const [id] = await knex('books').insert({
      title: req.body.title,
      author: req.body.author,
      publication_date: req.body.publicationDate,
      genre: req.body.genre,
      page_count: req.body.pageCount,
    });
    
    const newBook = await knex('books').where({ id }).first();
    res.status(201).json(toCamelCase(newBook));
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la création du livre' });
  }
});

app.put('/books/:id', validateBook, async (req, res) => {
  try {
    const updated = await knex('books')
      .where({ id: req.params.id })
      .update({
        title: req.body.title,
        author: req.body.author,
        publication_date: req.body.publicationDate,
        genre: req.body.genre,
        page_count: req.body.pageCount,
        updated_at: knex.fn.now()
      });

    updated ? res.json(toCamelCase(await knex('books').where({ id: req.params.id }).first())) 
           : res.status(404).json({ error: 'Livre non trouvé' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la mise à jour du livre' });
  }
});

app.delete('/books/:id', async (req, res) => {
  try {
    const deleted = await knex('books').where({ id: req.params.id }).del();
    deleted ? res.status(204).end() : res.status(404).json({ error: 'Livre non trouvé' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la suppression du livre' });
  }
});

const PORT = 3000;
app.listen(PORT, () => console.log(`API démarrée sur http://localhost:${PORT}`));