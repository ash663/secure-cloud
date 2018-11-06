var NodeRSA = require('node-rsa');
if (typeof localStorage === "undefined" || localStorage === null) {
  var LocalStorage = require('node-localstorage').LocalStorage;
  localStorage = new LocalStorage('./scratch');
}
var fs = require('fs');
var dir = 'data'; //Data directory
var keys = 'keys';

//For Public, private key pair
var keypair = require('keypair');
var crypto = require('crypto');
var algorithm = 'aes-256-ctr';

//New public-private key pair module URSA
//var ursa = require('ursa');


var bcrypt = require('bcryptjs'),
    Q = require('q'),
    config = require('./config.js'), //config file contains all tokens and other private info
    db = require('orchestrate')(config.db); //config.db holds Orchestrate token


//used in local-signup strategy
exports.localReg = function (username, password, email) {
  var deferred = Q.defer();
  var hash = bcrypt.hashSync(password, 8);
  var user = {
    "username": username,
    "password": hash,
    "email:": email,
    "avatar": "http://placepuppy.it/images/homepage/Beagle_puppy_6_weeks.JPG"
  }
  //check if username is already assigned in our database
  db.get('local-users', username)
  .then(function (result){ //case in which user already exists in db
    console.log('username already exists');
    deferred.resolve(false); //username already exists
  })
  .fail(function (result) {//case in which user does not already exist in db
      console.log(result.body);
      if (result.body.message == 'The requested items could not be found.'){
        console.log('Username is free for use');

        //Creating user directory in 'data' directory
        if(!fs.existsSync(dir+'/'+username)) {
          console.log("Creating directory");
          fs.mkdirSync(dir+'/'+username);
          fs.mkdirSync(dir+'/'+username+'/files');
          fs.mkdirSync(dir+'/'+username+'/'+keys);
          fs.mkdirSync(dir+'/'+username+'/'+keys+'/files');
        }
        //Generate public, private key pair for user
        var pair = keypair([bits=2048], e=65537);
        var safeKey = pair['private'];
        var key = new NodeRSA(pair['private']);
        //console.log(pair);
        //console.log(ursa.isKey(pair));
        //Store keypair, private key is stored in encrypted form
        var pubKey = username+'.pubKey';
        var privKey = username+'.privKey';
        var recKey = username+'.recKey';
        //store publicKey
        fs.writeFileSync(dir+'/'+username+'/'+keys+'/'+pubKey, pair['public']);

        //encrypt the private key
        var cipher = crypto.createCipher(algorithm, hash);
        var crypted = cipher.update(pair['private'],'utf8','hex');
        crypted += cipher.final('hex');
        // console.log(pair['private']);
        //store the encrypted private key
        fs.writeFileSync(dir+'/'+username+'/'+keys+'/'+privKey, crypted);

        // console.log("TESTING");
        //var privateKey = ursa.generatePrivateKey();
        //console.log(privateKey.getPrivateExponent());

        //create recovery key
        //var cipherRecovery = crypto.createCipher(algorithm, pair['private']);
        //var recoverykey = cipherRecovery.update(pair['private'], 'utf8', 'hex');
        //recoverykey += cipherRecovery.final('hex');
        //console.log(recoverykey);
        //console.log("Recovery key encrypted\n");

         //var decipher = crypto.createDecipher(algorithm, pair['public']);
         //var dec = decipher.update(text,'hex','utf8')
         //dec += decipher.final('utf8');
         //console.log(dec);

         //create recovery key using new method
        //  var newCrypto = require('crypto');
         //var abc = Buffer.from(pair['private'], 'utf8');
         //console.log(Type(pair['private']));
         //console.log(pair['private'].length);

         //console.log(newCrypto.privateEncrypt(pair['private'], new Buffer(pair['private'])));
         //pair['private'] = pair['private'].toString('utf8');
         //var recoveryKey = newCrypto.privateEncrypt(pair['private'], new Buffer(pair['private'], 'utf8'));
         var recoveryKey = key.encryptPrivate(pair['private']);
         //console.log("Happening");
         //console.log(recoveryKey);
         fs.writeFileSync(dir+'/'+username+'/'+keys+'/'+recKey, recoveryKey);
         //decrypting recovery key for TESTING
         //console.log('-----------------------');
        // console.log(key.decryptPublic(recoveryKey).toString());
        localStorage.setItem(username+'.privKey', pair['private']);

        db.put('local-users', username, user)
        .then(function () {
          console.log("USER: " + user);
          deferred.resolve(user);
        })
        .fail(function (err) {
          console.log("PUT FAIL:" + err.body);
          deferred.reject(new Error(err.body));
        });
      } else {
        deferred.reject(new Error(result.body));
      }
  });

  return deferred.promise;
};

//check if user exists
    //if user exists check if passwords match (use bcrypt.compareSync(password, hash); // true where 'hash' is password in DB)
      //if password matches take into website
  //if user doesn't exist or password doesn't match tell them it failed
exports.localAuth = function (username, password) {
  var deferred = Q.defer();

  db.get('local-users', username)
  .then(function (result){
    console.log("FOUND USER");
    var hash = result.body.password;
    console.log(hash);
    console.log(bcrypt.compareSync(password, hash));
    if (bcrypt.compareSync(password, hash)) {
      const decipher = crypto.createDecipher(algorithm, hash);
      var privKeyPath = __dirname+"/data/"+username+"/keys/"+username+".privKey";

      fs.readFile(privKeyPath, function(err, EprivKey) {
        if (err) throw err;
        else {
          // console.log(EprivKey);
          var privKey = decipher.update(EprivKey.toString(), 'hex', 'utf8');
          privKey += decipher.final('utf8');
          //console.log(privKey);

          localStorage.setItem(username+'.privKey', privKey);
        }
      });

      deferred.resolve(result.body);
    } else {
      console.log("PASSWORDS NOT MATCH");
      deferred.resolve(false);
    }
  }).fail(function (err){
    if (err.body.message == 'The requested items could not be found.'){
          console.log("COULD NOT FIND USER IN DB FOR SIGNIN");
          deferred.resolve(false);
    } else {
      deferred.reject(new Error(err));
    }
  });

  return deferred.promise;
}
