require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult, ValidationError } = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const knex = require('knex');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./swagger.yaml');

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Configuration Knex avec SQLite
const db = knex({
  client: 'sqlite3',
  connection: {
    filename: process.env.DB_FILENAME,
  },
  useNullAsDefault: true,
});

// Configuration Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  },
  tls: {
    rejectUnauthorized: process.env.NODE_ENV === 'production' // Autorise les certificats auto-signés en dev
  }
});

// Middleware d'authentification final
app.use(express.json());
const authMiddleware = (roles = []) => {
  return async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentification requise' });

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      const freshUser = await db('users')
        .where({ id: decoded.userId })
        .first();

      if (!freshUser) {
        return res.status(401).json({ error: 'Utilisateur introuvable' });
      }

      if (roles.length > 0 && !roles.includes(freshUser.role)) {
        return res.status(403).json({ error: 'Permissions insuffisantes' });
      }

      if (!freshUser.email_verified) {
        return res.status(403).json({ error: 'Email non vérifié' });
      }

      req.user = {
        id: freshUser.id,
        role: freshUser.role,
        email: freshUser.email
      };

      next();
    } catch (error) {
      console.error('[AUTH ERROR]', error.message);
      res.status(401).json({ 
        error: 'Session expirée ou invalide',
        ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
      });
    }
  };
};

// Middleware de validation
const validate = (validations) => {
  return async (req, res, next) => {
    console.log('Données brutes reçues:', JSON.stringify(req.body, null, 2));
    await Promise.all(validations.map(validation => validation.run(req)));
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Erreurs de validation:', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  };
};

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

// Route de test
app.get('/config-check', (req, res) => {
  res.json({
    frontendUrl: process.env.FRONTEND_URL,
    env: process.env.NODE_ENV
  });
});

// Route de test SMTP
app.get('/test-email', async (req, res) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: "test@mail.com",
      subject: 'Test SMTP Réussi 🚀',
      html: '<h1>Configuration SMTP Valide !</h1>'
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Erreur SMTP:', error);
    res.status(500).json({ 
      error: 'Échec d\'envoi d\'email',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});

// Route de login
app.post('/login',
  validate([
    body('email').isEmail(),
    body('password').notEmpty()
  ]),
  async (req, res) => {
    const { email, password } = req.body;
    
    const user = await db('users').where({ email }).first();
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        role: user.role,
        email_verified: user.email_verified
      }, 
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  }
);

// Route de registration
app.post('/register',
  validate(
    [
    body('username')
      .trim()
      .notEmpty().withMessage('Le nom d\'utilisateur est requis')
      .isLength({ min: 3 }).withMessage('3 caractères minimum'),

    body('email')
      .isEmail().withMessage('Email invalide'),

    body('password')
      .isLength({ min: 6 }).withMessage('6 caractères minimum') 
      .matches(/\d/).withMessage('Doit contenir un chiffre')
      
  ]),
  async (req, res) => {
    try {
      console.log('\n=== NOUVELLE INSCRIPTION ===');
      console.log('Données reçues:', req.body);

      const { username, email, password } = req.body;
      
      // Vérification email existant
      console.log('Vérification email en base...');
      const existingUser = await db('users').where({ email }).orWhere({ username }).first();
      if (existingUser) {
        const conflictField = existingUser.email === email ? 'email' : 'username';
        return res.status(400).json({ 
          error: `${conflictField} déjà utilisé` 
        });
      }

      // Hachage mot de passe
      console.log('Génération du salt...');
      const salt = await bcrypt.genSalt(10);
      console.log('Hachage du mot de passe...');
      const passwordHash = await bcrypt.hash(password, salt);

      // Insertion utilisateur
      console.log('Insertion en base de données...');
      const [userId] = await db('users').insert({
        username: username.trim(),
        email,
        password_hash: passwordHash,
        role: 'user',
        verify_token: crypto.randomBytes(20).toString('hex'),
        email_verified: false
      });

      // Récupération utilisateur créé
      console.log('Récupération du nouvel utilisateur...');
      const newUser = await db('users').where({ id: userId }).first();
      console.log('Utilisateur créé:', newUser);

      // Envoi email de vérification
      if (process.env.NODE_ENV !== 'test') {
        console.log('Préparation de l\'email...');
        const verificationUrl = `${process.env.FRONTEND_URL || `http://localhost:${process.env.PORT}`}/verify-email?token=${newUser.verify_token}`;
        
        console.log('Envoi de l\'email à:', email);
        await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: email,
          subject: 'Vérification d\'email',
          html: `Cliquez <a href="${verificationUrl}">ici</a> pour vérifier votre email`
        });
      }

      console.log('Inscription réussie !');
      res.status(201).json({ 
        message: 'Utilisateur créé', 
        verification_url: `http://localhost:${process.env.PORT}/verify-email?token=${newUser.verify_token}`
      });

      } catch (error) {
        console.error('Erreur SQL:', error.message);
      
        if (error.message.includes('SQLITE_CONSTRAINT: UNIQUE constraint failed')) {
          const column = error.message.split('users.')[1].trim();
          return res.status(400).json({ 
            error: `Le ${column} est déjà utilisé` 
          });
        }
      
        res.status(500).json({ 
          error: 'Erreur technique',
          ...(process.env.NODE_ENV === 'development' && { details: error.message })
        });
      }
  }
);

// Vérification d'email
app.get('/verify-email', async (req, res) => {
  const { token } = req.query;

  try {
    const user = await db('users')
      .where({ verify_token: token })
      .first();

    if (!user) {
      return res.status(400).json({ error: 'Token invalide' });
    }

    await db('users')
      .where({ id: user.id })
      .update({
        email_verified: true,
        verify_token: null
      });

    res.json({ message: 'Email vérifié avec succès' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de vérification' });
  }
});

// Mot de passe oublié
app.post('/forgot-password',
  validate([body('email').isEmail()]),
  async (req, res) => {
    try {
      const { email } = req.body;
      const user = await db('users').where({ email }).first();
      if (!user) return res.json({ message: 'Si l\'email existe, un lien a été envoyé' });

      const resetToken = crypto.randomBytes(20).toString('hex');
      await db('users')
        .where({ id: user.id })
        .update({
          reset_token: resetToken,
          reset_token_expiry: Date.now() + 3600000
        });

      // Envoi email en dev et prod
      if (process.env.NODE_ENV !== 'test') {
        const resetUrl = `${process.env.FRONTEND_URL || `http://localhost:${process.env.PORT}`}/reset-password?token=${resetToken}`;
        await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: email,
          subject: 'Réinitialisation de mot de passe',
          html: `Cliquez <a href="${resetUrl}">ici</a> pour réinitialiser votre mot de passe`
        });
      }

      res.json({ 
        message: 'Un email de réinitialisation a été envoyé',
        reset_url: `http://localhost:${process.env.PORT}/reset-password?token=${resetToken}`
      });
    } catch (error) {
      console.error('Erreur forgot-password:', error);
      res.status(500).json({ 
        error: 'Erreur d\'envoi d\'email',
        details: process.env.NODE_ENV === 'development' ? error.message : null
      });
    }
  }
);

// Réinitialisation du mot de passe
app.post('/reset-password',
  validate([
    body('token').notEmpty(),
    body('password').isLength({ min: 6 })
  ]),
  async (req, res) => {
    const { token, password } = req.body;

    try {
      const user = await db('users')
        .where({ reset_token: token })
        .where('reset_token_expiry', '>', Date.now())
        .first();

      if (!user) {
        return res.status(400).json({ error: 'Token invalide ou expiré' });
      }

      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);

      await db('users')
        .where({ id: user.id })
        .update({
          password_hash: passwordHash,
          reset_token: null,
          reset_token_expiry: null
        });

      res.json({ message: 'Mot de passe mis à jour avec succès' });
    } catch (error) {
      res.status(500).json({ error: 'Erreur de réinitialisation' });
    }
  }
);
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
  authMiddleware(),
  validate([
    body('title').trim().notEmpty(),
    body('author').trim().notEmpty(),
    body('publicationDate').isISO8601(),
    body('genre').trim().notEmpty(),
    body('pageCount').isInt({ min: 1 })
  ]),
  async (req, res) => {
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
  authMiddleware(),
  validate([
    body('title').optional().trim().notEmpty(),
    body('author').optional().trim().notEmpty(),
    body('publicationDate').optional().isISO8601(),
    body('genre').optional().trim().notEmpty(),
    body('pageCount').optional().isInt({ min: 1 })
  ]),
  async (req, res) => {
    try {
      const updated = await db('books')
        .where({ id: req.params.id })
        .update({
          title: req.body.title,
          author: req.body.author,
          publication_date: req.body.publicationDate,
          genre: req.body.genre,
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

app.delete('/books/:id', authMiddleware(['admin']), async (req, res) => {
  try {
    const deleted = await db('books').where({ id: req.params.id }).del();
    deleted ? res.status(204).end() : res.status(404).json({ error: 'Livre non trouvé' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de suppression du livre' });
  }
});

// Gestion des erreurs
app.use((err, req, res, next) => {
  if (err instanceof ValidationError) {
    return res.status(400).json({ 
      error: 'Données invalides',
      details: err.array() 
    });
  }

  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Token JWT invalide' });
  }

  console.error(err.stack);
  res.status(500).json({ 
    error: 'Erreur interne du serveur',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));