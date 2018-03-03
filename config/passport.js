// Strategy archetype used to generate new authentication strategies
var LocalStrategy = require('passport-local').Strategy;

// User schema we created. Each user will look just about the same.
var User = require('../app/models/user');

module.exports = function(passport) {
    // serialize determines which data of the user object should be stored in the session.
    // The result of the serializeUser method is attached to the session as 
    // req.session.passport.user = {id: xyz}
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // Corresponds to the key of the user object that was given to the done function above.
    // The object attached to the session is what is used to retrieved the key again.
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // Strategy that will perform the local signup operation
    passport.use('local-signup', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allow us to pass back the entire request to the callback
    },
    function(req, email, password, done){
        // asynchronous
        // User.findOne wont fire unless data is sent back
        process.nextTick(function() {
            // find a user whose email is the same as the forms email
            // we a re checking to see if the user trying to login already exists
            User.findOne({'local.email': email }, function(err, user) {
                if (err) {
                    return done(err);
                }

                if (user) {
                    return done(null, false, req.flash('signupMessage', 'That email is already taken'));
                } else {
                    var newUser = new User();
                    newUser.local.email = email;
                    newUser.local.password = newUser.generateHash(password);

                    newUser.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, newUser);
                    });
                }
            });
        });
    }));

    // Function that will perform the local login strategy.
    passport.use('local-login', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    },
    function(req, email, password, done) {
        User.findOne({ 'local.email': email }, function(err, user) {
            if (err)
                return done(err);
            
            if (!user)
                return done(null, false, req.flash('loginMessage', 'No user found'));
            
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Oops! Wrong password'));

            return done(null, user);
        });
    }));
};