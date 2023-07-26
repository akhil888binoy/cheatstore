import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
/*These lines import the bcrypt and jsonwebtoken modules,
 as well as the User model from the models/User.js file.*/

/* REGISTER USER */
export const register = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      picturePath,
      friends,
      location,
      occupation,
    } = req.body;

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: passwordHash,
      picturePath,
      friends,
      location,
      occupation,
      viewedProfile: Math.floor(Math.random() * 10000),
      impressions: Math.floor(Math.random() * 10000),
    });
    const savedUser = await newUser.save();
    res.status(201).json(savedUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/*  This code defines the register function, 
which is used to register a new user.
The function takes the user's first name, last name, 
email, password, and other information as input, and
then creates a new User object. 
The password is hashed using the bcrypt.hash() function, 
and the salt is stored with the hashed password. 
The new User object is then saved to the database.*/

/* LOGGING IN */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email });
    if (!user) return res.status(400).json({ msg: "User does not exist. " });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials. " });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    delete user.password;
    res.status(200).json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/*This code defines the login function,
which is used to log in a user. 
The function takes the user's email and password as input,
and then tries to find the user in the database. 
If the user is found, the bcrypt.compare() function is used to
compare the password provided by the user to the password stored in the database.
If the passwords match, a JWT token is generated and the user is logged in. 
The JWT token is a secure way to identify the user 
and allow them to access protected resources.*/

/* The token in res.status(200).json({ token, user }); is 
a JSON Web Token (JWT).
A JWT is a small, self-contained token that is 
used to authenticate users. 
It is a secure way to identify a user and allow 
them to access protected resources.

The token in this code is generated using 
the jwt.sign() function. 
The jwt.sign() function takes two arguments:
the claims and the secret. 
The claims are a set of properties that are 
associated with the token. In this case, the only 
claim is the user's ID.
The secret is a string that is used to sign the token.
The signature is used to verify that the token has not 
been tampered with.

The token is then returned to the user in the response.
The user can then use the token to access protected resources.

Here is an explanation of the JSON object that is
returned in the response:

token: This is the JWT token.
user: This is the user object. The user object is
included in the response so that the client can 
access the user's information without 
having to make another request to the server. */
