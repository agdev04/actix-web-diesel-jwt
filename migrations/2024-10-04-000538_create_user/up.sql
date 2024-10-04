-- Your SQL goes here
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR NOT NULL,
  email VARCHAR NOT NULL,
  password VARCHAR NOT NULL,
  profile_picture VARCHAR,
  role VARCHAR NOT NULL DEFAULT 'user',
  status VARCHAR NOT NULL DEFAULT 'active'
)