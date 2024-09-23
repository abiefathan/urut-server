const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./database.json'); // Data untuk endpoint utama
const userdbPath = './users.json'; // Data untuk endpoint /users

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789';
const expiresIn = '1h';

// Create token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  try {
    return jwt.verify(token, SECRET_KEY);
  } catch (err) {
    return null;
  }
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  const userData = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  return userData.users.find(user => user.email === email && user.password === password) !== undefined;
}

// Middleware to check if user is authenticated for specific routes
server.use((req, res, next) => {
  // Bypass authorization for /orders, /database, /recruitment, and others
  if (req.path.startsWith('/orders') || req.path.startsWith('/database') || req.path.startsWith('/recruitment')) {
    return next(); // Skip authentication
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader.split(' ')[0] !== 'Bearer') {
    return res.status(401).json({ status: 401, message: 'Error in authorization format' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ status: 401, message: 'Access token is invalid or expired' });
  }

  req.user = decoded; // Store role from token in request object
  next();
});

// Login endpoint
server.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ status: 400, message: 'Email and password are required' });
  }

  if (!isAuthenticated({ email, password })) {
    return res.status(401).json({ status: 401, message: 'Incorrect email or password' });
  }

  const userData = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  const user = userData.users.find(user => user.email === email);
  const access_token = createToken({ role: user.role });
  res.status(200).json({ access_token });
});

// Register New User
server.post('/auth/register', (req, res) => {
  const { email, password, nama, alamat, role } = req.body;

  if (!email || !password || !nama || !alamat || !role) {
    return res.status(400).json({ status: 400, message: 'All fields are required' });
  }

  if (isAuthenticated({ email, password })) {
    return res.status(400).json({ status: 400, message: 'Email and Password already exist' });
  }

  fs.readFile(userdbPath, (err, fileData) => {
    if (err) {
      return res.status(500).json({ status: 500, message: err.message });
    }

    let userData = JSON.parse(fileData.toString());
    let last_item_id = userData.users[userData.users.length - 1]?.id || 0;

    userData.users.push({
      id: last_item_id + 1,
      email,
      password,
      nama,
      alamat,
      role
    });

    fs.writeFile(userdbPath, JSON.stringify(userData, null, 2), (err) => {
      if (err) {
        return res.status(500).json({ status: 500, message: err.message });
      }

      const access_token = createToken({ role });
      res.status(200).json({ access_token });
    });
  });
});

// Get all users
server.get('/users', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader.split(' ')[0] !== 'Bearer') {
    return res.status(401).json({ status: 401, message: 'Access token required' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ status: 401, message: 'Access token is invalid or expired' });
  }

  const userData = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  res.json(userData);
});

// Get a user by ID
server.get('/users/:id', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader.split(' ')[0] !== 'Bearer') {
    return res.status(401).json({ status: 401, message: 'Access token required' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ status: 401, message: 'Access token is invalid or expired' });
  }

  const userData = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  const user = userData.users.find(u => u.id === parseInt(req.params.id));
  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ status: 404, message: 'User not found' });
  }
});

// Update a user by ID
server.put('/users/:id', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader.split(' ')[0] !== 'Bearer') {
    return res.status(401).json({ status: 401, message: 'Access token required' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ status: 401, message: 'Access token is invalid or expired' });
  }

  const { email, password, nama, alamat } = req.body;
  const userData = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  const userIndex = userData.users.findIndex(u => u.id === parseInt(req.params.id));

  if (userIndex !== -1) {
    userData.users[userIndex] = {
      id: parseInt(req.params.id),
      email,
      password,
      nama,
      alamat
    };

    fs.writeFileSync(userdbPath, JSON.stringify(userData, null, 2));
    res.json(userData.users[userIndex]);
  } else {
    res.status(404).json({ status: 404, message: 'User not found' });
  }
});

// Delete a user by ID
server.delete('/users/:id', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader.split(' ')[0] !== 'Bearer') {
    return res.status(401).json({ status: 401, message: 'Access token required' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ status: 401, message: 'Access token is invalid or expired' });
  }

  const userData = JSON.parse(fs.readFileSync(userdbPath, 'UTF-8'));
  const userIndex = userData.users.findIndex(u => u.id === parseInt(req.params.id));

  if (userIndex !== -1) {
    userData.users.splice(userIndex, 1);
    fs.writeFileSync(userdbPath, JSON.stringify(userData, null, 2));
    res.status(204).end();
  } else {
    res.status(404).json({ status: 404, message: 'User not found' });
  }
});

// Use JSON Server router
server.use(router);

server.listen(8000, () => {
  console.log('API NYA UDH JALAN DISINI >>> http://localhost:8000');
});
