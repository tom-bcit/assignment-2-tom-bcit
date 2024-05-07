require("./utils.js");

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const joi = require('joi');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const port = process.env.PORT || 3000;

const app = express();

const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false, 
  resave: true
}
));

// Define routes here

app.use(express.static(__dirname + "/public"));

app.get('/', (req, res) => {
  var name = req.session.name;
  var loggedIn = req.session.authenticated;
  res.render("index", {loggedIn: loggedIn, name: name});
});

app.get('/signup', (req, res) => {
  res.render("signup");
});

app.post('/signupSubmit', async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = joi.object({
    name: joi.string().required(),
    email: joi.string().email().required(),
    password: joi.string().required()
  });
  
  const validationResult = schema.validate({name, email, password});

  if (validationResult.error != null) {
    res.redirect('/signup?error=${validationResult.error}');
    return;
  }

  var hashedPassword = bcrypt.hashSync(password, saltRounds);
  await userCollection.insertOne({name: name, email: email, password: hashedPassword});
  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
	res.redirect('/members');
  
});

app.get('/login', (req, res) => {
  res.render("login");
});

app.post('/loggingIn', async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = joi.object({
    email: joi.string().email().required(),
    password: joi.string().required()
  });

  const validationResult = schema.validate({email, password});

  if (validationResult.error != null) {
    res.redirect('/loggingIn?error=${validationResult.error}');
    return;
  }

  var result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, _id: 1}).toArray();
  if (result.length != 1) {
		res.redirect("/loginFail");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		req.session.authenticated = true;
		req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		res.redirect("/loginFail");
		return;
	}
});

app.get('/loginFail', (req, res) => {
  res.render("loginFail");
});

app.get('/members', (req, res) => {
  var validSession = req.session.authenticated;
  if (!validSession) {
    res.redirect('/');
    return;
  } else {
    var rng = Math.round(Math.random()*2);
    res.render("members", {name: req.session.name, rng: rng});
  }
});

app.get('/logout', (req, res) => {
  req.session.authenticated = false;
  req.session.destroy();
  res.redirect('/');
});

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});