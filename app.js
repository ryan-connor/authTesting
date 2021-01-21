const express = require('express');
const path = require('path');
const session = require('express-session');
const passport= require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const Schema = mongoose.Schema; 
const config = require('./config.js');
const bcrypt = require('bcryptjs');

const mongoDb = config.mongoConfig;
mongoose.connect(mongoDb, {useUnifiedTopology: true, useNewUrlParser: true});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'mongo connection error'));

const User = mongoose.model(
    'User',
    new Schema( {
        username: {type: String, required: true},
        password: {type: String, required: true}
    }) 
);

const app = express();
app.set('views', __dirname);
app.set('view engine', 'ejs');

//passport middleware

passport.use(new LocalStrategy((username, password, done)=> {
    User.findOne({username: username}, (err, user) => {
        if (err) {
            return done(err);
        };
        if (!user) {
            return done(null, false, {msg: "Incorrect Username"});
        }
        bcrypt.compare(password, user.password, (err, res) => {
                if (res) {
                    return done(null, user);
                } else {
                    return done(null, false, {msg: "Incorrect Password"});
                }
            })
    });
}) 
);

passport.serializeUser( function (user,done) {
    done( null, user.id);
});

passport.deserializeUser( function (id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});


app.use(session({secret: 'cats', resave: false, saveUninitialized: true}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({extended: false}));

//middleware using locals to make current user accessible across app
app.use( (req,res, next)=> {
    res.locals.currentUser = req.user;
    next();
});


app.get('/', (req,res) => {
    res.render('index', {user: req.user});
});

app.get('/signUpForm', (req,res) => {
    res.render('signUpForm');

});

//not a safe way to create users/store passwords, just for quick testing/practice
app.post("/signUpForm", (req,res, next) => {

    bcrypt.hash(req.body.password, 10, (err, hashedPassword)=> {
        if (err){
        console.log("error hashing password");
        return next(err);
    }
    else {
        
        //if hash worked
        const user= new User({
            username: req.body.username,
            password: hashedPassword
        }).save((err)=> {
            if (err) {
                console.log('save error');
                return next(err);
            };
            res.redirect("/");
        });
    };
});
});

app.post('/logIn', passport.authenticate("local", {
    successRedirect: '/',
    failureRedirect: '/'
})
);

app.get('/logOut', (req, res) => {
    req.logout();
    res.redirect('/');
});


app.listen(3000, ()=> console.log('app listening on port 3000!'));
