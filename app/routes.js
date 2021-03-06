module.exports = function(app, passport) {
    console.log('setting up routes');
    app.get('/', function(req, res) {
        res.render('index.ejs');
    });

    app.get('/login', function (req, res) {
        res.render('login.ejs', { message: req.flash('loginMessage')})
    });

    app.get('/signup', function(req, res) {
        res.render('signup.ejs', { message: req.flash('signupMessage')});
    })

    // app.post('/signup', do all our passport stuff here);

    app.get('/profile', isLoggedIn, function(req, res) {
        res.render('profile.ejs', {
            user: req.user
        });
    });


    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });

    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect: '/profile',
        failureRedirect: '/signup',
        failureRedirect: true
    }));

    app.post('/login', passport.authenticate('local-login', {
        successRedirect: '/profile',
        failureRedirect: '/login',
        failureRedirect: true
    }))
}

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated())
        return next();
    
    res.redirect('/');
}