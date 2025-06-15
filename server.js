// =============================================================================
// cBOT - Investment Platform - Final Backend v3
// Author: Gemini
// Description: Complete backend with deposit/withdrawal system,
//              password recovery, and configured to serve the frontend.
// =============================================================================

// -----------------------------------------------------------------------------
// 1. DEPENDENCY IMPORTS
// -----------------------------------------------------------------------------
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto'); // 'crypto' module for secure token generation

// -----------------------------------------------------------------------------
// 2. INITIAL CONFIGURATION
// -----------------------------------------------------------------------------
dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// Serve static files (frontend) from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Environment variable validation
if (!process.env.MONGO_URI || !process.env.JWT_SECRET || !process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.error("ERROR: Required environment variables are not set. Please configure your .env file.");
    process.exit(1);
}

// -----------------------------------------------------------------------------
// 3. MONGOOSE MODELS (SCHEMAS)
// -----------------------------------------------------------------------------

// UserSchema with fields for password reset
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    withdrawalPassword: { type: String, required: true },
    balance: { type: Number, default: 0 },
    isVerified: { type: Boolean, default: false },
    isAdmin: { type: Boolean, default: false },
    isBlocked: { type: Boolean, default: false },
    verificationToken: { type: String },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const PlanSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    minAmount: { type: Number, required: true },
    durationDays: { type: Number, required: true },
    roiPercentage: { type: Number, required: true },
    isActive: { type: Boolean, default: true }
});
const Plan = mongoose.model('Plan', PlanSchema);

const BotSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
    investedAmount: { type: Number, required: true },
    expectedProfit: { type: Number, required: true },
    startDate: { type: Date, default: Date.now },
    endDate: { type: Date, required: true },
    isCompleted: { type: Boolean, default: false }
});
const Bot = mongoose.model('Bot', BotSchema);

const DepositMethodSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    accountInfo: { type: String, required: true },
    instructions: { type: String, required: true },
    isActive: { type: Boolean, default: true }
});
const DepositMethod = mongoose.model('DepositMethod', DepositMethodSchema);

const TransactionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['DEPOSIT', 'WITHDRAWAL', 'INVESTMENT', 'PROFIT'], required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['COMPLETED', 'PENDING', 'FAILED'], default: 'COMPLETED' },
    method: { type: String },
    userTransactionId: { type: String },
    description: { type: String },
    createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

// -----------------------------------------------------------------------------
// 4. NODEMAILER CONFIG & MIDDLEWARES
// -----------------------------------------------------------------------------
const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS } });

const authMiddleware = (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        res.status(401).json({ message: 'Access denied or invalid token.' });
    }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user || !user.isAdmin) {
            return res.status(403).json({ message: 'Access denied. Administrator permission required.' });
        }
        next();
    } catch (error) {
        res.status(500).json({ message: 'Error verifying administrator permissions.' });
    }
};

// -----------------------------------------------------------------------------
// 5. API ROUTES
// -----------------------------------------------------------------------------

// ==> AUTHENTICATION ROUTES <==
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
    const { name, email, password, withdrawalPassword } = req.body;
    if (!name || !email || !password || !withdrawalPassword) return res.status(400).json({ message: 'Please fill in all fields.' });
    try {
        if (await User.findOne({ email })) return res.status(400).json({ message: 'A user with this email is already registered.' });
        const salt = await bcrypt.genSalt(10);
        const user = new User({
            name, email,
            password: await bcrypt.hash(password, salt),
            withdrawalPassword: await bcrypt.hash(withdrawalPassword, salt),
            verificationToken: uuidv4(),
        });
        await user.save();
        const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email?token=${user.verificationToken}`;
        await transporter.sendMail({
            to: user.email, from: `"cBOT Platform" <${process.env.GMAIL_USER}>`, subject: 'Verify your cBOT account',
            html: `<p>Welcome to cBOT! Please click the link below to verify your account:</p><a href="${verificationUrl}">${verificationUrl}</a>`
        });
        res.status(201).json({ message: 'Registration successful! A verification email has been sent.' });
    } catch (error) { res.status(500).json({ message: 'Server error during registration.' }); }
});

authRouter.get('/verify-email', async (req, res) => {
    try {
        const user = await User.findOne({ verificationToken: req.query.token });
        if (!user) return res.status(400).send('<h1>Invalid or expired verification token.</h1>');
        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();
        res.send('<h1>Email verified successfully! You can now log in.</h1>');
    } catch (error) { res.status(500).send('<h1>Server error during email verification.</h1>'); }
});

authRouter.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Please provide email and password.' });
    try {
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Invalid credentials.' });
        if (!user.isVerified) return res.status(403).json({ message: 'Your account has not been verified. Please check your email.' });
        if (user.isBlocked) return res.status(403).json({ message: 'Your account is blocked. Please contact support.' });
        const token = jwt.sign({ id: user.id, name: user.name, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, isAdmin: user.isAdmin } });
    } catch (error) { res.status(500).json({ message: 'Server error during login.' }); }
});

authRouter.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(200).json({ message: 'If a user with that email exists, a recovery link has been sent.' });
        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // Expires in 1 hour
        await user.save();
        const resetURL = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}`;
        await transporter.sendMail({
            to: user.email, from: `"cBOT Platform" <${process.env.GMAIL_USER}>`, subject: 'cBOT Password Reset',
            html: `<p>You requested a password reset. Click the link to proceed:</p><a href="${resetURL}">${resetURL}</a><p>If you did not request this, please ignore this email.</p>`
        });
        res.status(200).json({ message: 'If a user with that email exists, a recovery link has been sent.' });
    } catch (error) { res.status(500).json({ message: 'Server error.' }); }
});

authRouter.post('/reset-password/:token', async (req, res) => {
    try {
        const { password } = req.body;
        const user = await User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        res.status(200).json({ message: 'Password has been reset successfully!' });
    } catch (error) { res.status(500).json({ message: 'Server error.' }); }
});

app.use('/api/auth', authRouter);

// ==> USER ROUTES <==
const userRouter = express.Router();

userRouter.get('/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -withdrawalPassword');
        const activeBots = await Bot.find({ user: req.user.id, isCompleted: false }).populate('plan');
        const transactions = await Transaction.find({ user: req.user.id }).sort({ createdAt: -1 }).limit(10);
        res.json({ user, activeBots, transactions });
    } catch (error) { res.status(500).json({ message: 'Error fetching dashboard data.' }); }
});

userRouter.get('/transactions', authMiddleware, async (req, res) => {
    try {
        const transactions = await Transaction.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.json(transactions);
    } catch (error) { res.status(500).json({ message: 'Error fetching transaction history.' }); }
});

userRouter.post('/invest', authMiddleware, async (req, res) => {
    const { planId, amount } = req.body;
    try {
        const plan = await Plan.findById(planId);
        const user = await User.findById(req.user.id);
        if (!plan || !plan.isActive) return res.status(404).json({ message: 'Plan not found or inactive.' });
        if (amount < plan.minAmount) return res.status(400).json({ message: `Investment amount must be at least ${plan.minAmount}.` });
        if (user.balance < amount) return res.status(400).json({ message: 'Insufficient balance.' });
        user.balance -= amount;
        const endDate = new Date();
        endDate.setDate(new Date().getDate() + plan.durationDays);
        await new Bot({ user: user.id, plan: planId, investedAmount: amount, expectedProfit: amount * (plan.roiPercentage / 100), endDate }).save();
        await new Transaction({ user: user.id, type: 'INVESTMENT', amount, description: `Investment in ${plan.name} plan` }).save();
        await user.save();
        res.status(201).json({ message: 'Investment successful!' });
    } catch (error) { res.status(500).json({ message: 'Error processing investment.' }); }
});

userRouter.post('/withdraw', authMiddleware, async (req, res) => {
    const { amount, withdrawalPassword, method } = req.body;
    if (!amount || !withdrawalPassword || !method) return res.status(400).json({ message: 'Amount, withdrawal password, and method are required.' });
    if (amount <= 0) return res.status(400).json({ message: 'Withdrawal amount must be positive.' });
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found.' });
        if (!await bcrypt.compare(withdrawalPassword, user.withdrawalPassword)) return res.status(400).json({ message: 'Incorrect withdrawal password.' });
        if (user.balance < amount) return res.status(400).json({ message: 'Insufficient balance.' });
        user.balance -= amount;
        await new Transaction({
            user: user.id, type: 'WITHDRAWAL', amount, status: 'PENDING', method,
            description: `Withdrawal request to: ${method}`
        }).save();
        await user.save();
        res.json({ message: 'Withdrawal request received. It will be processed shortly.' });
    } catch (error) { res.status(500).json({ message: 'Error processing withdrawal.' }); }
});

userRouter.get('/deposit-methods', authMiddleware, async (req, res) => {
    const methods = await DepositMethod.find({ isActive: true });
    res.json(methods);
});

userRouter.post('/deposit', authMiddleware, async (req, res) => {
    const { amount, methodId, userTransactionId } = req.body;
    if (!amount || !methodId || !userTransactionId) return res.status(400).json({ message: 'Amount, method, and transaction ID are required.' });
    try {
        const depositMethod = await DepositMethod.findById(methodId);
        if (!depositMethod || !depositMethod.isActive) return res.status(404).json({ message: 'Deposit method not found or inactive.' });
        await new Transaction({
            user: req.user.id, type: 'DEPOSIT', amount: parseFloat(amount),
            status: 'PENDING', method: depositMethod.name, userTransactionId,
            description: `Deposit request via ${depositMethod.name}`
        }).save();
        res.status(201).json({ message: 'Deposit request sent successfully. Please wait for approval.' });
    } catch (error) { res.status(500).json({ message: 'Error processing deposit request.' }); }
});

app.use('/api/user', userRouter);

// ==> ADMIN ROUTES <==
const adminRouter = express.Router();

// User Management
adminRouter.get('/users', (req, res) => User.find().select('-password -withdrawalPassword').then(u => res.json(u)));
adminRouter.put('/users/:id/block', (req, res) => User.findByIdAndUpdate(req.params.id, { isBlocked: true }, { new: true }).then(u => res.json(u)));
adminRouter.put('/users/:id/unblock', (req, res) => User.findByIdAndUpdate(req.params.id, { isBlocked: false }, { new: true }).then(u => res.json(u)));

// Plan Management
adminRouter.post('/plans', (req, res) => new Plan(req.body).save().then(p => res.status(201).json(p)));
adminRouter.get('/plans', (req, res) => Plan.find().then(p => res.json(p)));
adminRouter.put('/plans/:id', (req, res) => Plan.findByIdAndUpdate(req.params.id, req.body, { new: true }).then(p => res.json(p)));
adminRouter.delete('/plans/:id', (req, res) => Plan.findByIdAndDelete(req.params.id).then(() => res.json({ message: 'Plan removed.' })));

// Deposit Method Management
adminRouter.post('/deposit-methods', (req, res) => new DepositMethod(req.body).save().then(m => res.status(201).json(m)));
adminRouter.get('/deposit-methods', (req, res) => DepositMethod.find().then(m => res.json(m)));
adminRouter.put('/deposit-methods/:id', (req, res) => DepositMethod.findByIdAndUpdate(req.params.id, req.body, { new: true }).then(m => res.json(m)));
adminRouter.delete('/deposit-methods/:id', (req, res) => DepositMethod.findByIdAndDelete(req.params.id).then(() => res.json({ message: 'Deposit method removed.' })));

// Transaction Management
adminRouter.get('/transactions', (req, res) => Transaction.find().populate('user', 'name email').sort({ createdAt: -1 }).then(t => res.json(t)));

adminRouter.put('/transactions/:id/approve', async (req, res) => {
    try {
        const tx = await Transaction.findById(req.params.id);
        if (!tx || tx.status !== 'PENDING') return res.status(400).json({ message: 'Transaction not found or already processed.' });
        if (tx.type === 'DEPOSIT') {
            const user = await User.findById(tx.user);
            user.balance += tx.amount;
            await user.save();
        }
        tx.status = 'COMPLETED';
        await tx.save();
        res.json(tx);
    } catch (e) { res.status(500).json({ message: 'Error approving transaction.' }); }
});

adminRouter.put('/transactions/:id/reject', async (req, res) => {
    try {
        const tx = await Transaction.findById(req.params.id);
        if (!tx || tx.status !== 'PENDING') return res.status(400).json({ message: 'Transaction not found or already processed.' });
        if (tx.type === 'WITHDRAWAL') {
            const user = await User.findById(tx.user);
            user.balance += tx.amount;
            await user.save();
        }
        tx.status = 'FAILED';
        await tx.save();
        res.json(tx);
    } catch (e) { res.status(500).json({ message: 'Error rejecting transaction.' }); }
});

app.use('/api/admin', authMiddleware, adminMiddleware, adminRouter);

// -----------------------------------------------------------------------------
// 6. 'CATCH-ALL' ROUTE FOR FRONTEND & SERVER INITIALIZATION
// -----------------------------------------------------------------------------
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Successfully connected to MongoDB Atlas.');
        app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
    })
    .catch(err => {
        console.error('Failed to connect to MongoDB Atlas:', err);
        process.exit(1);
    });
