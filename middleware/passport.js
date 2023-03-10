const passport = require('passport');
const {Strategy} = require('passport-local');
const User = require('../models')
const md5 = require('md5')

async function authenticate(username, password, done) {
    //fetch user from database
    const user = await User.findOne({
        where: {
            email: username
        }
    });
    //if no user, or passwords do not match, call done with failure message
    if (!user || md5(password) !== user.password) {
        return done(null, false, {message: 'incorrect email or password'})
    }
    //passed authentication, so user passes
    return done(null, {
        id: user.id,
        username: user.email,
        displayName: user.first_name
    });
}

const validationStrategy = new Strategy({
    usernameField: 'email',
    password: 'password'
    },
    authenticate);

passport.use(validationStrategy);

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, {id: user.id, username: user.email, displayName: user.displayName});
    })
})

passport.deserializeUser(async function (user, cb) {
    //const dbUser = await User.findByPK(user.id);
    process.nextTick(function () {
        return cb(null, user);
    });
});

module.exports.passport = passport;

