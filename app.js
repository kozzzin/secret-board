var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const mongoose = require('mongoose');

const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const MongoStore = require('connect-mongo')(session);
const crypto = require('crypto');

const { check, validationResult } = require('express-validator');



const dotenv = require('dotenv').config();
const User = require('./models/user');
const Message = require('./models/message');


const mongoDb = process.env.DB;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

// where to store sessions
const sessionStore = new MongoStore(
  {mongooseConnection: db, collection: 'sessions'}
);

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
const { Console } = require('console');

var app = express();

app.use(session(
  {
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore
  }
));

function hashPassword(password) {
  const salt = crypto.randomBytes(32).toString('hex');
  const hash =
    crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return {
    salt,
    hash
  }
}


function validatePassword(password, hash, salt) {
  const hashToVerify =
    crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === hashToVerify;
}

passport.use(new LocalStrategy(
  function(username, password, done) {
    User.findOne({ username: username })
      .then((user) => {
        if (!user) return done(null,false);

        const isValid = validatePassword(password, user.hash, user.salt);

        if (isValid) {
          return done(null, user);
        } else {
          return done(null, false)
        }
      }).catch((err) => {
        done(err);
      })
  }
));

passport.serializeUser(function(user,cb) {
  console.log('serialize', user);
  cb(null, { id: user._id, username: user.username });
});

passport.deserializeUser(function(id,cb) {
  console.log('deserialize',id);
  User.findById(id.id, function(err,user) {
    if (err) return cb(err);
    console.log('user',user);
    return cb(null,user);
  })
})

app.use(passport.initialize());
app.use(passport.session());
app.use(passport.authenticate('session'));


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


app.use((req,res,next) => {
  console.log(req.session);
  next();
})


app.get('/', function(req, res, next) {
  Message.find()
    .populate('author')
    .sort({'date':-1})
    .then(messages => {
      res.render('index', { 
        title: 'Secret message board',
        body: req.body,
        user: req.user,
        messages: messages
       });
    })
});


app.use((req,res,next) => {
  console.log(req.user);
  next();
})

app.get(
  '/login',
  (req, res, next) => res.render(
  'login',
  {
    title: 'Log In',
    user: req.user
  }));

app.get(
  '/signup',
  (req, res, next) => res.render(
    'signup',
    {
      title: 'Sign Up',
      body:{},
      user: req.user
    }));

app.post(
  '/login',
  passport
    .authenticate(
      'local',
      {
        successRedirect: '/',
        failureRedirect: '/login'
    }),
  (err, req,res,next) => {
    if (err) console.log(err);
    console.log('auth',req.isAuthenticated());
    res.send(req.body);
  });

app.get(
  '/logout',
  (req,res,next) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/login');
  });
});

app.post(
  '/signup',
    check(['name','surname','username','password','passwordConfirm'])
      .trim()
      .escape()
      .toLowerCase(),
    check('password')
      .exists(),
    check(
      'passwordConfirm',
      'passwordConfirmation field must have the same value as the password field',
    )
      .exists()
      .custom((value, { req }) => {
        console.log(value);
        return value === req.body.password;
      }),

  (req,res,next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render(
        'signup',
        {
          title: 'Error on password confirmation',
          err: errors.array()[0]['msg'],
          body: req.body,
          user: req.user
        }
      );
    }

    const hash = hashPassword(req.body.password);

    User.init()
      .then(() => {
        const user = User.create({
          name: req.body.name,
          surname: req.body.surname,
          username: req.body.username,
          hash: hash.hash,
          salt: hash.salt,
          isAdmin: false,
          isMember: false
        }, function (err, user) {
          if (err) {
            return next(err);
          }
          return res.redirect('/login');
        })
      })
      .catch((err) => {
        return next(err);
      })
  }
);


app.get('/newmember', (req,res,next) => {
  if (req.isAuthenticated()) {
    if (req.user.isMember) return res.redirect('/');
    return res.render('newmember', {
      title: 'secret place',
      user: req.user
    });
  }
  return res.redirect('/login');
});


app.post(
  '/newmember',
  check(
    'secretMessage',
    'You don\'t know our secret. Sorry!',
  )
    .trim()
    .escape()
    .exists()
    .custom((value, { req }) => {
      return value === process.env.BOARDSECRET;
    }),
  (req,res,next) => {
    const errors = validationResult(req);
    console.log(errors);
    if (!errors.isEmpty()) {
      return res.render('newmember', {
        title: errors.array()[0]['msg'],
        user: req.user,
      });
    }
    User.findByIdAndUpdate(req.user._id, { isMember: true}, (err,updated) => {
      if (err) return next(err);
      return res.redirect('/');
    })
    // return res.redirect('/'); 

  });


app.get('/newmessage', (req,res,next) => {
  if (req.isAuthenticated()) {
    return res.render('newmessage', {
      title: 'New message',
      user: req.user
    });
  }
  return res.redirect('/login');
});

app.post('/newmessage', (req,res,next) => {
  if (req.isAuthenticated()) {
    console.log(req.body.message)
    Message.create({
      title: req.body.title,
      text: req.body.message,
      author: req.user._id,
    },
    function(err,message) {
      if (err) return next(err);
      console.log(message);
      return res.redirect('/');
    });
    // return res.render('newmessage', {
    //   title: 'New message',
    //   user: req.user
    // });
  }
  // return res.redirect('/login');
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});




module.exports = app;
