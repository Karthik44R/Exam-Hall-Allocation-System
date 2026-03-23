-- ============================================
-- EXAM ALLOC - DATABASE SCHEMA
-- MySQL 8+ Compatible
-- Run: mysql -u root -p < schema.sql
-- ============================================

CREATE DATABASE IF NOT EXISTS exam_seating;
USE exam_seating;

-- Drop in reverse dependency order
DROP TABLE IF EXISTS unallocated_students;
DROP TABLE IF EXISTS seat_allocations;
DROP TABLE IF EXISTS allocation_logs;
DROP TABLE IF EXISTS students;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS halls;
DROP TABLE IF EXISTS users;

-- --------------------------------------------
-- TABLE 1: halls
-- --------------------------------------------
CREATE TABLE halls (
    hall_id    VARCHAR(20)  PRIMARY KEY,
    hall_name  VARCHAR(100) NOT NULL,
    capacity   INT          NOT NULL CHECK (capacity > 0),
    total_rows INT          NOT NULL CHECK (total_rows > 0),
    total_cols INT          NOT NULL CHECK (total_cols > 0),
    created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- --------------------------------------------
-- TABLE 2: users
-- User accounts (coordinator / invigilator / administrator)
-- --------------------------------------------
CREATE TABLE users (
    id         INT          AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(80)  NOT NULL UNIQUE,
    password   VARCHAR(255) NOT NULL,
    role       ENUM('coordinator','invigilator','administrator') NOT NULL,
    created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- Default seed accounts (passwords will be auto-migrated to bcrypt on first server start)
INSERT IGNORE INTO users (username, password, role)
VALUES
  ('coordinator', 'coord123', 'coordinator'),
  ('invigilator', 'invig123', 'invigilator');

-- --------------------------------------------
-- TABLE 3: sessions
-- --------------------------------------------
CREATE TABLE sessions (
    token      VARCHAR(64)  PRIMARY KEY,
    username   VARCHAR(100) NOT NULL,
    role       VARCHAR(50)  NOT NULL,
    created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- --------------------------------------------
-- TABLE 4: students
-- --------------------------------------------
CREATE TABLE students (
    student_id   VARCHAR(50)  PRIMARY KEY,
    student_name VARCHAR(150) NOT NULL,
    subject_code VARCHAR(30)  NOT NULL,
    created_at   TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- --------------------------------------------
-- TABLE 5: seat_allocations
-- --------------------------------------------
CREATE TABLE seat_allocations (
    allocation_id INT         AUTO_INCREMENT PRIMARY KEY,
    student_id    VARCHAR(50) NOT NULL,
    hall_id       VARCHAR(20) NOT NULL,
    seat_row      INT         NOT NULL,
    seat_col      INT         NOT NULL,
    seat_label    VARCHAR(20),
    allocated_at  TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE,
    FOREIGN KEY (hall_id)    REFERENCES halls(hall_id)       ON DELETE CASCADE,
    UNIQUE KEY unique_seat    (hall_id, seat_row, seat_col),
    UNIQUE KEY unique_student (student_id)
);

-- --------------------------------------------
-- TABLE 6: unallocated_students
-- Stores student_name + subject_code directly
-- to avoid join failures if student is deleted
-- --------------------------------------------
CREATE TABLE unallocated_students (
    student_id   VARCHAR(50)  PRIMARY KEY,
    student_name VARCHAR(150) NOT NULL DEFAULT '',
    subject_code VARCHAR(30)  NOT NULL DEFAULT '',
    reason       VARCHAR(255) DEFAULT  'Insufficient hall capacity',
    logged_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- --------------------------------------------
-- TABLE 7: allocation_logs
-- --------------------------------------------
CREATE TABLE allocation_logs (
    log_id                INT  AUTO_INCREMENT PRIMARY KEY,
    total_students        INT,
    total_allocated       INT,
    total_unallocated     INT,
    constraint_violations INT  DEFAULT 0,
    duration_ms           INT,
    status                ENUM('SUCCESS','PARTIAL','FAILED') DEFAULT 'SUCCESS',
    message               TEXT,
    run_at                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- --------------------------------------------
-- VIEWS
-- --------------------------------------------

CREATE OR REPLACE VIEW v_seating_chart AS
SELECT
    sa.hall_id,
    h.hall_name,
    h.capacity   AS hall_capacity,
    h.total_rows AS hall_rows,
    h.total_cols AS hall_cols,
    sa.seat_row,
    sa.seat_col,
    sa.seat_label,
    s.student_id,
    s.student_name,
    s.subject_code
FROM seat_allocations sa
JOIN students s ON sa.student_id = s.student_id
JOIN halls    h ON sa.hall_id    = h.hall_id
ORDER BY sa.hall_id, sa.seat_row, sa.seat_col;

CREATE OR REPLACE VIEW v_subject_per_hall AS
SELECT
    sa.hall_id,
    s.subject_code,
    COUNT(*) AS student_count
FROM seat_allocations sa
JOIN students s ON sa.student_id = s.student_id
GROUP BY sa.hall_id, s.subject_code
ORDER BY sa.hall_id, s.subject_code;

CREATE OR REPLACE VIEW v_hall_summary AS
SELECT
    h.hall_id,
    h.hall_name,
    h.capacity,
    h.total_rows,
    h.total_cols,
    COUNT(sa.student_id)              AS seats_filled,
    h.capacity - COUNT(sa.student_id) AS seats_remaining
FROM halls h
LEFT JOIN seat_allocations sa ON h.hall_id = sa.hall_id
GROUP BY h.hall_id, h.hall_name, h.capacity, h.total_rows, h.total_cols;
-- To remove all users
-- USE exam_seating;

-- DELETE FROM sessions;
-- DELETE FROM users;

-- Reset auto-increment so IDs start from 1 again
-- ALTER TABLE users AUTO_INCREMENT = 1;