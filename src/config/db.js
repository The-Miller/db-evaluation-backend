const mysql = require('mysql2');

const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
});

db.connect(err => {
  if (err) {
    console.error('Erreur de connexion à MySQL :', err);
    throw err;
  }
  console.log('Connecté à MySQL avec succès');
});

module.exports = db;