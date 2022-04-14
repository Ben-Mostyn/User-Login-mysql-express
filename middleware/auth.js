const bcrypt = require("bcrypt");
const ExtractJWT = require("passport-jwt").ExtractJwt;
const JWTStrategy = require("passport-jwt").Strategy;
const LocalStrategy = require("passport-local").Strategy;

const User = require("../models/user");

//takes name and password from the user model
const register = async (name, password, next) => {
  //saltRounds is for hashing the password, we parse int this because we need saltrounds to be a number
  const saltRounds = parseInt(process.env.SALT_ROUNDS);

  try {
    if (!name) {
      throw new Error("No name was commited");
    }

    //This creates the salt to hash the password
    const salt = await bcrypt.genSalt(saltRounds);

    //we pass through the password and the salt we just created to hash the password
    const hash = await bcrypt.hash(password, salt);

    //We use build here instead of create, because build makes it not go to the database like create would.
    //When you use create, it saves the instance and instantly sends it off to the connected database which is what we dont want.
    const user = await User.build({ name, password: hash });

    try {
      //Speaks for itself, saves the user. Save also sends it to the database.
      await user.save();
      next(null, user);
    } catch (error) {
      next(null, {});
    }
  } catch (error) {
    //This is saying push the error to the next function
    next(error);
  }
};
const login = async (name, password, next) => {
  try {
    const user = await User.findOne({ where: { name } });

    if (!user) {
      return next(null, false, { msg: "Incorrect Username" });
    }

    const match = await bcrypt.compare(password, user.password);
    return match
      ? next(null, user)
      : next(null, false, { msg: "Incorrect password" });
  } catch (error) {
    return next(error);
  }
};

// the token has the user profile saved into it from the login functon
const verify = (token, next) => {
  try {
    next(null, token.user);
  } catch (error) {
    next(error);
  }
};

//usernameField and passwordField have to be them names exactly
//creating a new local strategy with two objects, which we then run through our register function
const registerStrategy = new LocalStrategy(
  { usernameField: "name", passwordField: "password" },
  register
);
const loginStrategy = new LocalStrategy(
  { usernameField: "name", passwordField: "password" },
  login
);

const verifyStrategy = new JWTStrategy(
  {
    secretOrKey: process.env.SECRET_KEY,
    jwtFromRequest: ExtractJWT.fromUrlQueryParameter("secret_token"),
  },
  verify
);

module.exports = {
  verifyStrategy,
  registerStrategy,
  loginStrategy,
};
