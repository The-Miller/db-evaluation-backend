const express = require('express');
const router = express.Router();
const db = require('../config/db');
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const pdf = require('pdf-parse');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = 'votre_cle_secrete_tres_longue_et_securisee';
const ENCRYPTION_KEY = '12345678901234567890123456789012'; // Clé de 32 caractères
const IV_LENGTH = 16;

// Configuration de multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}.enc`);
  },
});
const upload = multer({ storage });

// Middleware pour vérifier le token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requis' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalide' });
    req.user = user;
    next();
  });
};

// Middleware pour vérifier le rôle
const restrictTo = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Accès interdit : rôle insuffisant' });
    }
    next();
  };
};

// Fonctions de chiffrement/déchiffrement
const encryptFile = (buffer) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return Buffer.concat([iv, encrypted]);
};

const decryptFile = (buffer) => {
  const iv = buffer.slice(0, IV_LENGTH);
  const encryptedText = buffer.slice(IV_LENGTH);
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  return Buffer.concat([decipher.update(encryptedText), decipher.final()]);
};

// Calcul de similarité Jaccard
const jaccardSimilarity = (str1, str2) => {
  const set1 = new Set(str1.split(/\s+/).filter(word => word.length > 2)); // Ignore mots courts
  const set2 = new Set(str2.split(/\s+/).filter(word => word.length > 2));
  const intersection = new Set([...set1].filter(x => set2.has(x)));
  const union = new Set([...set1, ...set2]);
  return union.size === 0 ? 0 : intersection.size / union.size;
};

// Inscription
router.post('/users', async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password || !role) {
    return res.status(400).json({ error: 'Email, mot de passe et rôle requis' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (email, password, role) VALUES (?, ?, ?)';
    db.query(query, [email, hashedPassword, role], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      const user = { id: result.insertId, email, role };
      const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
      res.status(201).json({ token, user });
    });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors du hachage du mot de passe' });
  }
});

// Connexion
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
  });
});

// Création d'exercice
router.post('/exercises', authenticateToken, restrictTo('teacher'), (req, res) => {
  const { teacher_id, title, content, correction } = req.body;
  if (req.user.id !== teacher_id) {
    return res.status(403).json({ error: 'Vous ne pouvez pas créer un exercice pour un autre professeur' });
  }
  const query = 'INSERT INTO exercises (teacher_id, title, content, correction) VALUES (?, ?, ?, ?)';
  db.query(query, [teacher_id, title, content, correction], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: result.insertId, teacher_id, title, content, correction });
  });
});

// Liste des exercices
router.get('/exercises', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM exercises';
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Soumission avec détection de plagiat
router.post('/submissions', authenticateToken, restrictTo('student'), upload.single('file'), async (req, res) => {
  const { student_id, exercise_id } = req.body;
  const file = req.file;

  if (!student_id || !exercise_id || !file) {
    return res.status(400).json({ error: 'Données manquantes' });
  }
  if (req.user.id !== parseInt(student_id)) {
    return res.status(403).json({ error: 'Vous ne pouvez pas soumettre pour un autre étudiant' });
  }

  // Chiffrer le fichier
  const fileBuffer = fs.readFileSync(file.path);
  const encryptedBuffer = encryptFile(fileBuffer);
  fs.writeFileSync(file.path, encryptedBuffer);

  const exerciseQuery = 'SELECT correction FROM exercises WHERE id = ?';
  db.query(exerciseQuery, [exercise_id], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'Exercice non trouvé' });

    const correction = results[0].correction || '';
    const encryptedData = fs.readFileSync(file.path);
    const decryptedBuffer = decryptFile(encryptedData);
    const pdfData = await pdf(decryptedBuffer);
    const studentAnswer = pdfData.text;

    // Vérification du plagiat
    const submissionsQuery = 'SELECT file_path FROM submissions WHERE exercise_id = ? AND student_id != ?';
    db.query(submissionsQuery, [exercise_id, student_id], async (err, pastSubmissions) => {
      if (err) return res.status(500).json({ error: err.message });

      let maxSimilarity = 0;
      for (const sub of pastSubmissions) {
        const pastFilePath = path.join(__dirname, '../../uploads', sub.file_path);
        const pastEncryptedData = fs.readFileSync(pastFilePath);
        const pastDecryptedBuffer = decryptFile(pastEncryptedData);
        const pastPdfData = await pdf(pastDecryptedBuffer);
        const pastAnswer = pastPdfData.text;
        const similarity = jaccardSimilarity(studentAnswer, pastAnswer);
        maxSimilarity = Math.max(maxSimilarity, similarity);
      }

      try {
        const response = await axios.post('http://localhost:11434/api/generate', {
          model: 'mistral',
          prompt: `Évalue cette réponse d’étudiant : "${studentAnswer}" par rapport à la correction : "${correction}". Fournis une note sur 20 et un feedback détaillé en français uniquement, au format suivant : "Note : X/20\nFeedback : [détails en français]".`,
          stream: false,
        });

        const iaResponse = response.data.response;
        const gradeMatch = iaResponse.match(/Note\s*:\s*(\d+)\/20/);
        const feedbackMatch = iaResponse.match(/Feedback\s*:\s*(.+)/);

        const grade = gradeMatch ? parseInt(gradeMatch[1], 10) : 0;
        const feedback = feedbackMatch ? feedbackMatch[1].trim() : 'Aucun feedback fourni';

        const query = 'INSERT INTO submissions (student_id, exercise_id, file_path, grade, feedback, plagiarism_score) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(query, [student_id, exercise_id, file.filename, grade, feedback, maxSimilarity], (err, result) => {
          if (err) return res.status(500).json({ error: err.message });
          res.status(201).json({ id: result.insertId, student_id, exercise_id, file_path: file.filename, grade, feedback, plagiarism_score: maxSimilarity });
        });
      } catch (error) {
        console.error('Erreur avec Ollama :', error);
        res.status(500).json({ error: 'Erreur lors de la correction automatique' });
      }
    });
  });
});

// Liste des soumissions
router.get('/submissions', authenticateToken, (req, res) => {
  let query;
  if (req.user.role === 'student') {
    query = `
      SELECT 
        s.id, s.student_id, s.exercise_id, s.file_path, s.grade, s.feedback, s.submitted_at, s.plagiarism_score,
        u.email AS student_email, e.title AS exercise_title
      FROM submissions s
      JOIN users u ON s.student_id = u.id
      JOIN exercises e ON s.exercise_id = e.id
      WHERE s.student_id = ?
    `;
    db.query(query, [req.user.id], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    });
  } else if (req.user.role === 'teacher') {
    query = `
      SELECT 
        s.id, s.student_id, s.exercise_id, s.file_path, s.grade, s.feedback, s.submitted_at, s.plagiarism_score,
        u.email AS student_email, e.title AS exercise_title
      FROM submissions s
      JOIN users u ON s.student_id = u.id
      JOIN exercises e ON s.exercise_id = e.id
    `;
    db.query(query, (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    });
  }
});

// Mise à jour d’une soumission
router.put('/submissions/:id', authenticateToken, restrictTo('teacher'), (req, res) => {
  const { id } = req.params;
  const { grade, feedback } = req.body;
  if (grade === undefined || !feedback) {
    return res.status(400).json({ error: 'Note et feedback requis' });
  }
  const query = 'UPDATE submissions SET grade = ?, feedback = ? WHERE id = ?';
  db.query(query, [grade, feedback, id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Soumission non trouvée' });
    res.json({ message: 'Soumission mise à jour' });
  });
});

module.exports = router;