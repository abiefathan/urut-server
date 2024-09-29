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

//
// Middleware
server.use((req, res, next) => {
  if (
    req.path.startsWith('/orders') || 
    req.path.startsWith('/price') || 
    req.path.startsWith('/bidAccept') ||
    req.path.startsWith('/bidPending') ||
    req.path.startsWith('/status') ||
    req.path.startsWith('/transactions') ||
    req.path.startsWith('/history') || // Ini pengecualian untuk /history
    req.path.startsWith('/recruitment') ||
    req.path.startsWith('/district') ||
    req.path.startsWith('/gender') ||
    req.path === '/auth/login' || 
    req.path === '/auth/register'
  ) {
    return next(); // Skip authentication
  }
  
  // Pengecekan JWT untuk endpoint lain yang tidak dikecualikan
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader.split(' ')[0] !== 'Bearer') {
    return res.status(401).json({ status: 401, message: 'Error in authorization format' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ status: 401, message: 'Access token is invalid or expired' });
  }

  req.user = decoded; 
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
  
  // Tambahkan email ke dalam payload token
  const access_token = createToken({ role: user.role, email: user.email });
  res.status(200).json({ access_token });
});

// Verify token function remains the same



// Register New User
server.post('/auth/register', (req, res) => {
  const { email, password, name, address, age, phoneNumber, gender, ktp, kk, role, district } = req.body;

  // Validasi input
  if (!email || !password || !name || !address || !age || !phoneNumber || !gender || !ktp || !kk || !role || !district) {
    return res.status(400).json({ status: 400, message: 'All fields are required' });
  }

  // Cek cek apa udah ada ges
  if (isAuthenticated({ email, password })) {
    return res.status(400).json({ status: 400, message: 'Email already exists' });
  }

  fs.readFile(userdbPath, (err, fileData) => {
    if (err) {
      return res.status(500).json({ status: 500, message: err.message });
    }

    let userData = JSON.parse(fileData.toString());
    let last_item_id = userData.users[userData.users.length - 1]?.id || 0;

    // Tambahkan pengguna baru ke data
    userData.users.push({
      id: last_item_id + 1,
      email,
      password,
      name,
      address,
      age,
      district, 
      phoneNumber,
      gender,
      ktp,
      kk,
      role
    });

    fs.writeFile(userdbPath, JSON.stringify(userData, null, 2), (err) => {
      if (err) {
        return res.status(500).json({ status: 500, message: err.message });
      }

      res.status(201).json("success registed"); // Menggunakan 201 Created
    });
  });
});


// Get all users (protected route)
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

// Get a user by ID (protected route)
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

// Update a user by ID (protected route)
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

  fs.readFile(userdbPath, (err, fileData) => {
    if (err) {
      return res.status(500).json({ status: 500, message: err.message });
    }

    let userData = JSON.parse(fileData.toString());
    const userIndex = userData.users.findIndex(u => u.id === parseInt(req.params.id));

    if (userIndex === -1) {
      return res.status(404).json({ status: 404, message: 'User not found' });
    }

    userData.users[userIndex] = { ...userData.users[userIndex], ...req.body }; 

    fs.writeFile(userdbPath, JSON.stringify(userData, null, 2), (err) => {
      if (err) {
        return res.status(500).json({ status: 500, message: err.message });
      }

      res.status(200).json(userData.users[userIndex]);
    });
  });
});


// Delete a user by ID (protected route)
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

  fs.readFile(userdbPath, (err, fileData) => {
    if (err) {
      return res.status(500).json({ status: 500, message: err.message });
    }

    let userData = JSON.parse(fileData.toString());
    const userIndex = userData.users.findIndex(u => u.id === parseInt(req.params.id));

    if (userIndex === -1) {
      return res.status(404).json({ status: 404, message: 'User not found' });
    }

    userData.users.splice(userIndex, 1); // Remove user

    fs.writeFile(userdbPath, JSON.stringify(userData, null, 2), (err) => {
      if (err) {
        return res.status(500).json({ status: 500, message: err.message });
      }

      res.status(204).send(); // No content
    });
  });
});


server.use(router);

server.listen(8000, () => {
  console.log('API NYA UDH JALAN DISINI >>> http://localhost:8000');
});
