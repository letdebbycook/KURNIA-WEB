const mysql = require("mysql2");

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "kurnia_db",
  port: "3306"
});

db.connect(err => {
  if (err) throw err;
  console.log("Database Connected ✅");
});

module.exports = db;
