//index.js/
var express = require('express'),
    exphbs = require('express-handlebars'),
    logger = require('morgan'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    methodOverride = require('method-override'),
    session = require('express-session'),
    passport = require('passport'),
    LocalStrategy = require('passport-local'),
    TwitterStrategy = require('passport-twitter'),
    GoogleStrategy = require('passport-google'),
    FacebookStrategy = require('passport-facebook');
    multer = require('multer');
    upload = multer({dest: './data/tmp/', rename: function(fieldname, originalname) {
      return filename;
    }});
var config = require('./config.js'); //config file contains all tokens and other private info

var db = require('orchestrate')(config.db); //config.db holds Orchestrate token


var config = require('./config.js'), //config file contains all tokens and other private info
    funct = require('./functions.js'); //funct file contains our helper functions for our Passport and database work

var app = express();
// app.use(multer);

var fs = require('fs');

var NodeRSA = require('node-rsa');
if (typeof localStorage === "undefined" || localStorage === null) {
  var LocalStorage = require('node-localstorage').LocalStorage;
  localStorage = new LocalStorage('./scratch');
}
var privKey;

var crypto = require('crypto');
var algorithm = 'aes-256-ctr';

var bcrypt = require('bcryptjs');

var dir = 'data'; //Data directory

//===============PASSPORT===============

//This section will contain our work with Passport
// Passport session setup.
passport.serializeUser(function(user, done) {
  console.log("serializing " + user.username);
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  console.log("deserializing " + obj);
  done(null, obj);
});

passport.use('local-signin', new LocalStrategy(
  {passReqToCallback : true}, //allows us to pass back the request to the callback
  function(req, username, password, done) {
    funct.localAuth(username, password)
    .then(function (user) {
      if (user) {
        console.log("LOGGED IN AS: " + user.username);
        req.session.success = 'You are successfully logged in ' + user.username + '!';
        done(null, user);
      }
      if (!user) {
        console.log("COULD NOT LOG IN");
        req.session.error = 'Could not log user in. Please try again.'; //inform user could not log them in
        done(null, user);
      }
    })
    .fail(function (err){
      console.log(err.body);
    });
  }
));


// Use the LocalStrategy within Passport to register/"signup" users.
passport.use('local-signup', new LocalStrategy(
  {passReqToCallback : true}, //allows us to pass back the request to the callback
  function(req, username, password, done) {
    funct.localReg(username, password)
    .then(function (user) {
      if (user) {
        console.log("REGISTERED: " + user.username);
        req.session.success = 'You are successfully registered and logged in ' + user.username + '!';
        done(null, user);
      }
      if (!user) {
        console.log("COULD NOT REGISTER");
        req.session.error = 'That username is already in use, please try a different one.'; //inform user could not log them in
        done(null, user);
      }
    })
    .fail(function (err){
      console.log(err.body);
    });
  }
));

//===============EXPRESS================
// Configure Express
app.use(logger('combined'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(methodOverride('X-HTTP-Method-Override'));
app.use(session({secret: 'supernova', saveUninitialized: true, resave: true}));
app.use(passport.initialize());
app.use(passport.session());

// Session-persisted message middleware
app.use(function(req, res, next){
  var err = req.session.error,
      msg = req.session.notice,
      success = req.session.success;

  delete req.session.error;
  delete req.session.success;
  delete req.session.notice;

  if (err) res.locals.error = err;
  if (msg) res.locals.notice = msg;
  if (success) res.locals.success = success;

  next();
});

// Configure express to use handlebars templates
var hbs = exphbs.create({
    defaultLayout: 'main', //we will be creating this layout shortly
});
app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');

//===============ROUTES===============

//This section will hold our Routes
//displays our homepage
app.use(express.static(__dirname + '/data'));


app.get('/', function(req, res){
  //show user files
  if(req.user != undefined) {

    var files = __dirname+"/data/"+req.user.username+"/files";

    fs.readdir(files, function(err, items) {
      var array=[];
      for(i=0; i<items.length; ++i) {
        array.push({index: i, file: items[i]});
      }
      res.render('home', {user: req.user, array: array});
    });
  }
  else {
    res.render('home', {user: req.user});
  }

});

//displays our signup page
app.get('/signin', function(req, res){
  res.render('signin');
});

app.get('/passwordloss', function(req, res) {
  res.render('passwordloss');
});

app.get('/downloadrecovery', function(req, res) {
  var file = "/data/"+req.user.username+"/keys/"+req.user.username+".recKey";
  res.render('downloadrecovery', {user: req.user, file: file});
});
//Download recovery file
app.get('/downloadRec', function(req, res) {
  var file = __dirname+"/data/"+req.user.username+"/keys/"+req.user.username+".recKey";
  res.download(file);
});
//Download user file
app.get('/downloadFile*', function(req, res) {
  var file = __dirname+"/data/"+req.user.username+"/files/"+req.query.download;
  var prKey = localStorage.getItem(req.user.username+'.privKey');
  var temp = __dirname+"/data/tmp/"+req.query.download;
  var fileKeyPath = __dirname+"/data/"+req.user.username+"/keys/files/"+req.query.download;

  // console.log(prKey);
  // var key = new NodeRSA(prKey);
  // key.setOptions({encryptionScheme: 'pkcs1'});
  var fileDecipher = crypto.createDecipher(algorithm, prKey);
  fs.readFile(fileKeyPath, function(err, randomNumber) {
    var fileKey = fileDecipher.update(randomNumber.toString(), 'hex', 'utf8');
    fileKey += fileDecipher.final('utf8');
    console.log(fileKey);




    fs.readFile(file, function(err, upFile) {
      //console.log(upFile);
      // var fileKey = key.decryptPublic(fileKeyPath);
      //Decrypting random number i.e. FileKey

      var decipher = crypto.createDecipher(algorithm, fileKey);
      var decryptedFile = decipher.update(upFile.toString(), 'hex', 'binary');
      decryptedFile += decipher.final('binary');
      var buffer = new Buffer(decryptedFile, "binary");

      // console.log(decryptedFile.toString());
      fs.writeFile(temp, buffer, function(err) {
        res.download(temp);
        // fs.unlink()
      });
    });
  });



});

//sends the request through our local signup strategy, and if successful takes user to homepage, otherwise returns then to signin page
app.post('/local-reg', passport.authenticate('local-signup', {
  successRedirect: '/downloadrecovery',
  failureRedirect: '/signin'
  })
);

//sends the request through our local login/signin strategy, and if successful takes user to homepage, otherwise returns then to signin page
app.post('/login', passport.authenticate('local-signin', {
  successRedirect: '/',
  failureRedirect: '/signin'
  })
);
//Upload file and encrypt it and store it
app.post('/upload', upload.single('uploadFile'), function(req, res) {
  //Random key is used to encrypt files. Random key is encrypted with user's private key and stored
  var randomNumber = (Math.random() * 10000000).toString();
  console.log(randomNumber);
  var prKey = localStorage.getItem(req.user.username+'.privKey');
  var fileCipher = crypto.createCipher(algorithm, prKey);

  var cipher = crypto.createCipher(algorithm, randomNumber);
  var oldPath=req.file.path;
  var newPath= __dirname+"/data/"+req.user.username+"/files/"+req.file.originalname;
  var fileKeyPath = __dirname+"/data/"+req.user.username+"/keys/files/"+req.file.originalname;
  fs.readFile(oldPath, function(err, data) {

    // fs.writeFile(newPath, data, function(err) {

      // var key = new NodeRSA(prKey);
      // key.setOptions({encryptionScheme: 'pkcs1'});
      //var uploadedFile = key.encrypt(new Buffer(data), 'base64');

      var uploadedFile = cipher.update(data, 'utf8','hex');
      uploadedFile += cipher.final('hex');

      fs.writeFile(newPath, uploadedFile, function(err) {
        fs.unlink(oldPath, function() {
          if(err) throw err;
        });
        //console.log(uploadedFile);
      });
      var fileKey = fileCipher.update(randomNumber, 'utf8','hex');
      fileKey += fileCipher.final('hex');
      // var fileKey = key.encryptPrivate(new Buffer(randomNumber));
      fs.writeFile(fileKeyPath, fileKey, function (err) {
        if (err) throw err;
      });

      // console.log(key.decrypt(uploadedFile).toString());
      console.log("Uploaded file");
      res.redirect('/');
    // });
  });
});

app.post('/recoverFiles', upload.single('uploadRecovery'), function(req, res) {
  var publicKeyPath = __dirname+"/data/"+req.body.username+"/keys/"+req.body.username+".pubKey";
  fs.readFile(publicKeyPath, function(err, publicKey) {
    var key = new NodeRSA(publicKey);
    fs.readFile(req.file.path, function(err, recoveryKey) {
      if(key.decryptPublic(recoveryKey)){
        //TODO: Store decrypted key. Encrypt with hash of new password. Reset password.
        var hash = bcrypt.hashSync(req.body.password, 8);
        var cipher = crypto.createCipher(algorithm, hash);
        var crypted = cipher.update(key.decryptPublic(recoveryKey).toString(),'utf8','hex');
        crypted += cipher.final('hex');
        fs.writeFileSync(dir+'/'+req.body.username+'/keys/'+req.body.username+'.privKey', crypted);

        //RESETTING PASSWORD
        var user ={
          "username": req.body.username,
          "password": hash,
          "avatar": "http://placepuppy.it/images/homepage/Beagle_puppy_6_weeks.JPG"
        }
        db.put('local-users', req.body.username, user)
        .then(function () {
          console.log("USER: " + user);
          res.redirect('/');
        });
      }

    });
  });
});



//logs user out of site, deleting them from the session, and returns to homepage
app.get('/logout', function(req, res){
  var name = req.user.username;
  console.log("LOGGIN OUT " + req.user.username)
  req.logout();
  res.redirect('/');
  req.session.notice = "You have successfully been logged out " + name + "!";
});

//===============PORT=================
var port = process.env.PORT || 5000; //select your port or let it pull from your .env file
app.listen(port);
console.log("listening on " + port + "!");
