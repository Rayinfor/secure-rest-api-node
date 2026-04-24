Secure REST API (Node.js)

This project is a simple secure REST API built with Node.js and Express.

It allows users to:

Register with an email and password

Log in and receive a JWT token

Access protected routes using that token

Passwords are hashed before being stored, and the API limits requests to reduce brute-force attempts.

How It Works

A user registers with /auth/register.

The password is hashed using bcrypt and stored in a local JSON file.

The user logs in via /auth/login.

A JWT token is generated and returned.

Protected routes require a valid Authorization: Bearer <token> header.

Tech Used

Node.js

Express

bcrypt (password hashing)

jsonwebtoken (JWT authentication)

express-rate-limit (basic protection)

Run Locally
npm install
npm start

Server runs on:

http://localhost:3000

Purpose of This Project

I made this project to demonstrate that i got some backend security fundamentals:

Authentication flow

Secure password storage

Token-based authorization

Middleware protection

Author: Rayane Khelifi
