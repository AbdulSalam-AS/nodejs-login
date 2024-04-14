const express = require("express");
const mysql = require("mysql");
const dotenv = require("dotenv");
// const hbs = require("hbs");
const path = require("path");
const cookieParser = require('cookie-parser');

dotenv.config({path : './.env'});

const app = express();

const db = mysql.createConnection({
    host : process.env.DATABASE_HOST,
    user : process.env.DATABASE_USER,
    password : process.env.DATABASE_PASSWORD,
    database : process.env.DATABASE
});
const publicDirectory = path.join(__dirname,"./public");

app.use(express.static(publicDirectory));

// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({extended : false}))


// Parse JSON bodies (as Sent by API Clients)
app.use(express.json());
app.use(cookieParser());

app.set("view engine", "hbs");


db.connect((error)=>{
    if(error){
        return console.log(error)
    }else{
        return console.log('Mysql Connected...')
    }
})



// Define Routes
app.use('/', require('./routes/pages'));
app.use('/auth', require('./routes/auth'));



app.listen('3000',()=>{console.log("Server started on port 3000")})
