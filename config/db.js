require('dotenv').config();
const sql = require('mssql');

// Configure SQL Server connection
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  server: process.env.DB_HOST,
  database: process.env.DB_NAME,
  options: {
    encrypt: true, // Use encryption for Azure SQL
    trustServerCertificate: true, // Change to true for local development
  }
};

async function connectToDb() {
  try {
    const pool = await sql.connect(dbConfig);
    console.log("Connected to SQL Server");
    return pool;
  } catch (error) {
    console.error("SQL Server Connection Error: ", error);
    throw error;
  }
}

module.exports = connectToDb;