CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('student', 'teacher') NOT NULL
);

CREATE TABLE exercises (
  id INT AUTO_INCREMENT PRIMARY KEY,
  teacher_id INT,
  title VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  correction TEXT,
  FOREIGN KEY (teacher_id) REFERENCES users(id)
);

CREATE TABLE submissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  student_id INT,
  exercise_id INT,
  file_path VARCHAR(255) NOT NULL,
  grade INT,
  feedback TEXT,
  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  plagiarism_score FLOAT DEFAULT 0,
  FOREIGN KEY (student_id) REFERENCES users(id),
  FOREIGN KEY (exercise_id) REFERENCES exercises(id)
);