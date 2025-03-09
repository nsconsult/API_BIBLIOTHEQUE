require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const knex = require('knex');

// Configuration Knex avec SQLite
const db = knex({
  client: 'sqlite3',
  connection: {
    filename: process.env.DB_FILENAME,
  },
  useNullAsDefault: true,
});

// Middleware d'authentification
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentification requise' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token invalide' });
  }
};

// Initialisation Express
const app = express();

// Middlewares
app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(helmet());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// Conversion snake_case -> camelCase
const toCamelCase = (book) => ({
  id: book.id,
  title: book.title,
  author: book.author,
  publicationDate: book.publication_date,
  genre: book.genre,
  pageCount: book.page_count,
  createdAt: book.created_at,
  updatedAt: book.updated_at,
});

// Routes Publiques
app.post('/login', async (req, res) => {
  // À remplacer par une vérification en base de données
  const validUser = {
    id: 1,
    username: 'admin',
    password: await bcrypt.hash('admin123', 10)
  };

  const { username, password } = req.body;
  
  if (username === validUser.username && await bcrypt.compare(password, validUser.password)) {
    const token = jwt.sign(
      { userId: validUser.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );
    return res.json({ token });
  }
  
  res.status(401).json({ error: 'Identifiants invalides' });
});

// Routes Livres
app.get('/books', async (req, res) => {
  try {
    const books = await db('books').select('*');
    res.json(books.map(toCamelCase));
  } catch (error) {
    res.status(500).json({ error: 'Erreur de récupération des livres' });
  }
});

app.get('/books/:id', async (req, res) => {
  try {
    const book = await db('books').where({ id: req.params.id }).first();
    book ? res.json(toCamelCase(book)) : res.status(404).json({ error: 'Livre non trouvé' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de récupération du livre' });
  }
});

app.post('/books', 
  authMiddleware,
  [
    body('title').trim().notEmpty(),
    body('author').trim().notEmpty(),
    body('publicationDate').isISO8601(),
    body('genre').trim().notEmpty(),
    body('pageCount').isInt({ min: 1 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const [id] = await db('books').insert({
        title: req.body.title,
        author: req.body.author,
        publication_date: req.body.publicationDate,
        genre: req.body.genre,
        page_count: req.body.pageCount
      });
      
      const newBook = await db('books').where({ id }).first();
      res.status(201).json(toCamelCase(newBook));
    } catch (error) {
      res.status(500).json({ error: 'Erreur de création du livre' });
    }
  }
);

app.put('/books/:id',
  authMiddleware,
  [
    body('title').optional().trim().notEmpty(),
    body('author').optional().trim().notEmpty(),
    body('publicationDate').optional().isISO8601(),
    body('genre').optional().trim().notEmpty(),
    body('pageCount').optional().isInt({ min: 1 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const updated = await db('books')
        .where({ id: req.params.id })
        .update({
          ...req.body,
          publication_date: req.body.publicationDate,
          page_count: req.body.pageCount,
          updated_at: db.fn.now()
        });

      if (!updated) return res.status(404).json({ error: 'Livre non trouvé' });
      
      const book = await db('books').where({ id: req.params.id }).first();
      res.json(toCamelCase(book));
    } catch (error) {
      res.status(500).json({ error: 'Erreur de mise à jour du livre' });
    }
  }
);

app.delete('/books/:id', authMiddleware, async (req, res) => {
  try {
    const deleted = await db('books').where({ id: req.params.id }).del();
    deleted ? res.status(204).end() : res.status(404).json({ error: 'Livre non trouvé' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de suppression du livre' });
  }
});

// Gestion des erreurs
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Erreur interne du serveur',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));