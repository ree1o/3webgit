require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(cookieParser());

const mongoURI = process.env.MONGO_URI;
if (!mongoURI) {
    console.error("Error: MONGO_URI is missing in .env file");
    process.exit(1);
}
mongoose.connect(mongoURI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.log("❌ MongoDB Connection Error:", err));

// Models
const Product = mongoose.model('Product', new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    description: String,
    category: String,
    stock: { type: Number, required: true, default: 0 }
}));

const User = mongoose.model('User', new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] }
}));

const Order = mongoose.model('Order', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    productIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true }],
    status: { type: String, default: 'pending', enum: ['pending', 'shipped', 'delivered'] },
    createdAt: { type: Date, default: Date.now }
}));

// Middleware
const authenticate = (req, res, next) => {
    const token = req.cookies.token || req.header("Authorization")?.split(" ")[1];
    if (!token) return res.status(401).json({ message: 'Access Denied. No Token Provided.' });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: 'Invalid Token' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access Denied. Admins Only.' });
    }
    next();
};

// Routes
app.get('/', (req, res) => res.send('E-commerce API is running 🚀'));

// 🔹 User Authentication
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'All fields are required' });

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'Email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });

        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error registering user', error: err.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'All fields are required' });

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

        res.json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ message: 'Error logging in', error: err.message });
    }
});

app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

// 🔹 Users Routes (Admin Only)
app.get('/users', authenticate, isAdmin, async (req, res) => {
    const users = await User.find();
    res.json(users);
});

app.get('/users/:id', authenticate, isAdmin, async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
});

app.put('/users/:id/role', authenticate, isAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        if (!['user', 'admin'].includes(role)) return res.status(400).json({ message: 'Invalid role' });

        const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
        res.json(user);
    } catch (err) {
        res.status(400).json({ message: 'Error updating role', error: err.message });
    }
});

// 🔹 Product Routes
app.post('/products', authenticate, isAdmin, async (req, res) => {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json(product);
});

app.get('/products', async (req, res) => {
    const products = await Product.find();
    res.json(products);
});

app.put('/products/:id', authenticate, isAdmin, async (req, res) => {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(product);
});

app.delete('/products/:id', authenticate, isAdmin, async (req, res) => {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted' });
});

// 🔹 Orders Routes
app.post('/orders', authenticate, async (req, res) => {
    const { productIds } = req.body;
    if (!productIds || productIds.length === 0) return res.status(400).json({ message: 'At least one product is required' });

    const order = new Order({ userId: req.user.id, productIds });
    await order.save();
    res.status(201).json(order);
});

app.get('/orders', authenticate, async (req, res) => {
    const orders = await Order.find({ userId: req.user.id }).populate('productIds');
    res.json(orders);
});

app.get('/orders/all', authenticate, isAdmin, async (req, res) => {
    const orders = await Order.find().populate('productIds userId');
    res.json(orders);
});

app.put('/orders/:id', authenticate, isAdmin, async (req, res) => {
    const order = await Order.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(order);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
