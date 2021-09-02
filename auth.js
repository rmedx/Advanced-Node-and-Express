const LocalStrategy = require('passport-local');
const passport = require('passport');
const bcrypt = require('bcrypt');
const ObjectID = require('mongodb').ObjectID;

module.exports = (app, myDataBase) => {
    passport.serializeUser((user, done) => {
        done(null, user._id);
      });
      passport.deserializeUser((id, done) => {
        myDataBase.findOne({_id: new ObjectID(id)}, (err, doc) => {
          done(null, doc);
        });
      });
      passport.use(new LocalStrategy(
        (username, password, done) => {
          myDataBase.findOne({username: username}, (err, user) => {
            if (err) {
              return done(err);
            }
            if (!user) {
              return done(null, false);
            }
            if (!bcrypt.compareSync(password, user.password)) {
              return done(null, false);
            }
            return done(null, user);
          })
        }
      ));
}