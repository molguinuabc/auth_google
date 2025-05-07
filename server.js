const express = require('express')
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth20').Strategy
const session = require('express-session')
const fs = require('fs')
const https = require('https')
require('dotenv').config()
const  forceSSL  = require('express-sslify')
const cors = require('cors')
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto =  require('crypto');
// csrfProtection = require('./csrfProtection');

const app = express()
app.use(cors({
    origin: 'https://localhost:9000',
    credentials: true}

));
app.use(cookieParser());
app.use(forceSSL.HTTPS())

const port = process.env.PORT || 3000

// SSL Options
const options = {
  key: fs.readFileSync('./key.pem'),
  cert: fs.readFileSync('./cert.pem')
}

app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true
  }
}))

app.use(passport.initialize())
app.use(passport.session())


const FRONTEND_URL = 'https://localhost:9000';

function generateXsrfToken(jwtToken) {
  const xsrfToken = crypto.createHmac('sha256', process.env.SECRET_KEY)
    .update(JSON.stringify(jwtToken))
    .digest('hex');
  return xsrfToken;
}

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  function(accessToken, refreshToken, profile, cb) {
    // Aquí puedes guardar el perfil del usuario en tu base de datos
    return cb(null, profile);
  }
));

passport.serializeUser((user, done) => {
  done(null, user)
})

passport.deserializeUser((id, done) => {
  // Aquí deberías buscar el usuario en la base de datos usando `id`
  done(null, id)
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
)

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: `/error` }),
  (req, res) => {
    const token = jwt.sign(req.user, process.env.SECRET_KEY, { expiresIn: '1h' });
    console.log("AUTH TOKEN GENERADO:",token);
    const xsrfToken = generateXsrfToken(token);

    res.cookie('auth_token', token, {
        httpOnly: false,
        secure: true,
        sameSite: 'strict',
        domain: 'localhost',
        maxAge: 900000 // 15 minutos
      });
      res.cookie('XSRF-TOKEN', xsrfToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        domain: 'localhost',
      });

    res.redirect(`/`)
   
  }
)

function validateAuth(req,res,next){
  const auth_token = req.cookies['auth_token']
  const xsrfToken = req.cookies['XSRF-TOKEN'];
  const authAuthToken = req.headers['authorization'];

  if(!auth_token || !xsrfToken || 
    generateXsrfToken(auth_token) !== xsrfToken) {
    res.status(401).send('Not Authorized');
    return;
  }
  next();


}

app.get('/login',(req,res) =>{
  res.send(`
    <form>
      <button type="button" onclick="window.location.href='/auth/google'">
        Authenticate with Google
      </button>
    </form>
  `);

});
// Logout route
app.get('/logout', (req, res) => {
    console.log('Logout');
    res.clearCookie('auth_token');
    res.clearCookie('XSRF-TOKEN');
    res.status(200).redirect(`/login`);
  });

  // Antes de regresar los datos valida que la llamada tenga las
  // cookies y headers adecuados con validateAuth
  app.get('/api/protected',validateAuth, (req, res) => {
    const token = req.cookies.auth_token;
    try {
      const decoded = jwt.verify(token, process.env.SECRET_KEY);
      res.json({ data: 'Información sensible', user: decoded });
    } catch (err) {
      res.status(401).json({ error: 'Token inválido o expirado' });
    }
  });

app.get('/', (req, res) => {
  res.send('Hola Mundo!')
})

// Ruta para simular una llamada del cliente
// Establece el header Auhtorization
// y redirige a la ruta protegida
app.get('/consulta',(req,res,next)=>{
  req.header['authorization'] = req.cookies.auth_token;
  res.redirect('/api/protected');
});

app.get('/dashboard', (req, res) => {
    console.log('Cookie: auth_token\n', req.cookies.auth_token);
    console.log('Cookie: XSRF-TOKEN\n', req.cookies['XSRF-TOKEN']);
    res.status(200).send({ message:'Hello World!'});
  })

https.createServer(options, app).listen(port, () => {
  console.log(`Server running at https://localhost:${port}`)
})