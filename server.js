const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Load environment variables - supports both .env and cctv.env
try {
  require('dotenv').config({ path: './cctv.env' });
} catch (error) {
  require('dotenv').config(); // Fallback to default .env
}

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Google Sheets setup
let auth;
try {
  auth = new google.auth.GoogleAuth({
    keyFile: 'credentials.json',
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
  });
} catch (error) {
  console.error('Error loading credentials.json:', error.message);
  console.log('Please make sure credentials.json exists in the root directory');
  process.exit(1);
}

const sheets = google.sheets({ version: 'v4', auth });
const SPREADSHEET_ID = process.env.SPREADSHEET_ID;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SPREADSHEET_ID || !JWT_SECRET) {
  console.error('Missing required environment variables: SPREADSHEET_ID or JWT_SECRET');
  process.exit(1);
}

// ... rest of your server code remains the same