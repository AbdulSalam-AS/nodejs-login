const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const brcypt = require('bcryptjs');
const bcrypt = require('bcryptjs/dist/bcrypt');
const { promisify } = require('util');

const db = mysql.createConnection({
    host     : process.env.DATABASE_HOST,
    user     : process.env.DATABASE_USER,
    password : process.env.DATABASE_PASSWORD,
    database : process.env.DATABASE
});

exports.register = async (req, res) => {
    
    // const name = req.body.name;
    // const email = req.body.email;
    // const password = req.body.password;
    // const passwordConfirm = req.body.passwordConfirm;

    const {name, email, password, passwordConfirm} = req.body;    

    db.query("SELECT email from users WHERE email = ?",[email], async(error, results) => {
        if(error){
            console.log(error);
        }

        if(results.length > 0){
            return res.render('register',{
                message: 'That email already Exists'
            })
        }else if(password !== passwordConfirm){
            return res.render('register',{
                message: 'Passwords do not match'
            });    
       }
            
        let hashedPassword = await brcypt.hash(password, 8);
        db.query('INSERT INTO users SET ?',{name: name, email: email, password: hashedPassword},(error,results)=>{
            if(error){
                console.log(error);
            }else{
                console.log(results)
                return res.render('register',{
                    messageOk : 'user registered'
                });
            }
        })
        
    });


}

exports.login = async(req, res) => {
    try{
        const {email, password} = req.body;
        if(!email || !password){
            return res.status(400).render('login',{
                message:'Please enter a username and password'
            })
        }

        db.query('SELECT * FROM users WHERE email = ?',[email], async(error, results)=>{
            if(!results || !(await bcrypt.compare(password, results[0].password))){
                return res.status(401).render('login',{
                    message:'Invalid username or password'
                });
            }else{
                const id = results[0].id;


                const token = jwt.sign({id: id}, process.env.JWT_SECRET,{
                    expiresIn: process.env.JWT_EXPIRES_IN
                });

                const cookieOptions = {
                    expires: new Date(
                        Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                    ),
                    httpOnly: true
                }
                res.cookie('jwt', token, cookieOptions);
                res.status(200).redirect("/");
            }
        })
    }   
    catch(error){
        console.log(error);
    }
};

exports.isLoggedIn = async(req, res, next) => {
    if( req.cookies.jwt){
        try{
            // Verify the token
            const decoded = await promisify(jwt.verify)(req.cookies.jwt,process.env.JWT_SECRET);
            console.log(decoded);
            
            
            //Check if the user still exists
            db.query('SELECT * FROM users WHERE id = ?',[decoded.id],(error, result) => {
                if(!result){
                    return next();
                }
                req.user = result[0];
                return next();
            });
        }catch(error){
            console.log(error);
            return next();
        }
    }
    else{
        next();
    }

}

exports.logout = async(req, res) => {
    res.cookie('jwt', 'logout', {
        expires: new Date(Date.now() + 2 * 1000),
        httpOnly: true
    });
    res.status(200).redirect('/');
}