// =============================================================================
// cBOT - Investment Platform - Final and Complete Backend
// Author: Gemini
// Version: 5.0 (Ready to Run)
// Description: Self-contained backend with all features including user auth,
//              password recovery, profile management, transactions, admin panel,
//              and frontend file serving.
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
const crypto = require('crypto');

// -----------------------------------------------------------------------------
// 2. INITIAL CONFIGURATION & SETUP
// -----------------------------------------------------------------------------
dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// Serve static files (frontend) from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Environment variable validation
if (!process.env.MONGO_URI || !process.env.JWT_SECRET || !process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.error("FATAL ERROR: Required environment variables are not set. Please configure your .env file.");
    process.exit(1);
}

// -----------------------------------------------------------------------------
// 3. MONGOOSE MODELS (DATABASE SCHEMAS)
// -----------------------------------------------------------------------------

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
// 4. MIDDLEWARES & NODEMAILER CONFIGURATION
// -----------------------------------------------------------------------------
const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS } });

const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader) return res.status(401).json({ message: 'Acesso negado. Nenhum token fornecido.' });
    
    const token = authHeader.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Acesso negado. Token mal formatado.' });

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        res.status(401).json({ message: 'Acesso negado ou token inválido.' });
    }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user || !user.isAdmin) {
            return res.status(403).json({ message: 'Acesso negado. Requer permissão de administrador.' });
        }
        next();
    } catch (error) {
        res.status(500).json({ message: 'Erro ao verificar permissões de administrador.' });
    }
};

// -----------------------------------------------------------------------------
// 5. API ROUTES
// -----------------------------------------------------------------------------

// ==> AUTHENTICATION ROUTES <==
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
    const { name, email, password, withdrawalPassword } = req.body;
    if (!name || !email || !password || !withdrawalPassword) return res.status(400).json({ message: 'Por favor, preencha todos os campos.' });
    try {
        if (await User.findOne({ email })) return res.status(400).json({ message: 'Um utilizador com este e-mail já está registado.' });
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
            to: user.email, from: `"Plataforma cBOT" <${process.env.GMAIL_USER}>`, subject: 'Verifique a sua conta cBOT',
            html: `<p>Bem-vindo à cBOT! Por favor, clique no link abaixo para verificar a sua conta:</p><a href="${verificationUrl}">${verificationUrl}</a>`
        });
        res.status(201).json({ message: 'Registo bem-sucedido! Um e-mail de verificação foi enviado.' });
    } catch (error) { res.status(500).json({ message: 'Erro no servidor durante o registo.' }); }
});

authRouter.get('/verify-email', async (req, res) => {
    try {
        const user = await User.findOne({ verificationToken: req.query.token });
        if (!user) return res.status(400).send('<h1>Token de verificação inválido ou expirado.</h1>');
        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();
        res.send('<h1>E-mail verificado com sucesso! Já pode fazer login.</h1>');
    } catch (error) { res.status(500).send('<h1>Erro no servidor durante a verificação do e-mail.</h1>'); }
});

authRouter.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Por favor, forneça e-mail e senha.' });
    try {
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Credenciais inválidas.' });
        if (!user.isVerified) return res.status(403).json({ message: 'A sua conta não foi verificada. Por favor, verifique o seu e-mail.' });
        if (user.isBlocked) return res.status(403).json({ message: 'A sua conta está bloqueada. Por favor, contacte o suporte.' });
        const token = jwt.sign({ id: user.id, name: user.name, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, isAdmin: user.isAdmin } });
    } catch (error) { res.status(500).json({ message: 'Erro no servidor durante o login.' }); }
});

authRouter.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(200).json({ message: 'Se um utilizador com esse e-mail existir, um link de recuperação foi enviado.' });
        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // Expira em 1 hora
        await user.save();
        const resetURL = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}`;
        await transporter.sendMail({
            to: user.email, from: `"Plataforma cBOT" <${process.env.GMAIL_USER}>`, subject: 'Recuperação de Senha cBOT',
            html: `<p>Solicitou a redefinição da sua senha. Clique no link para prosseguir:</p><a href="${resetURL}">${resetURL}</a><p>Se não solicitou esta alteração, por favor, ignore este e-mail.</p>`
        });
        res.status(200).json({ message: 'Se um utilizador com esse e-mail existir, um link de recuperação foi enviado.' });
    } catch (error) { res.status(500).json({ message: 'Erro no servidor.' }); }
});

authRouter.post('/reset-password/:token', async (req, res) => {
    try {
        const { password } = req.body;
        const user = await User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ message: 'O token de recuperação é inválido ou expirou.' });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        res.status(200).json({ message: 'Senha redefinida com sucesso!' });
    } catch (error) { res.status(500).json({ message: 'Erro no servidor.' }); }
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
    } catch (error) { res.status(500).json({ message: 'Erro ao buscar dados do dashboard.' }); }
});

userRouter.get('/transactions', authMiddleware, async (req, res) => {
    try {
        const transactions = await Transaction.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.json(transactions);
    } catch (error) { res.status(500).json({ message: 'Erro ao buscar histórico de transações.' }); }
});

userRouter.post('/invest', authMiddleware, async (req, res) => {
    const { planId, amount } = req.body;
    try {
        const plan = await Plan.findById(planId);
        const user = await User.findById(req.user.id);
        if (!plan || !plan.isActive) return res.status(404).json({ message: 'Plano não encontrado ou inativo.' });
        if (amount < plan.minAmount) return res.status(400).json({ message: `O valor do investimento deve ser de no mínimo ${plan.minAmount}.` });
        if (user.balance < amount) return res.status(400).json({ message: 'Saldo insuficiente.' });
        user.balance -= amount;
        const endDate = new Date();
        endDate.setDate(new Date().getDate() + plan.durationDays);
        await new Bot({ user: user.id, plan: planId, investedAmount: amount, expectedProfit: amount * (plan.roiPercentage / 100), endDate }).save();
        await new Transaction({ user: user.id, type: 'INVESTMENT', amount, description: `Investimento no plano ${plan.name}` }).save();
        await user.save();
        res.status(201).json({ message: 'Investimento realizado com sucesso!' });
    } catch (error) { res.status(500).json({ message: 'Erro ao processar o investimento.' }); }
});

userRouter.post('/withdraw', authMiddleware, async (req, res) => {
    const { amount, withdrawalPassword, method } = req.body;
    if (!amount || !withdrawalPassword || !method) return res.status(400).json({ message: 'Valor, senha de saque e método são obrigatórios.' });
    if (amount <= 0) return res.status(400).json({ message: 'O valor do saque deve ser positivo.' });
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Utilizador não encontrado.' });
        if (!await bcrypt.compare(withdrawalPassword, user.withdrawalPassword)) return res.status(400).json({ message: 'Senha de saque incorreta.' });
        if (user.balance < amount) return res.status(400).json({ message: 'Saldo insuficiente.' });
        user.balance -= amount;
        await new Transaction({
            user: user.id, type: 'WITHDRAWAL', amount, status: 'PENDING', method,
            description: `Pedido de levantamento para: ${method}`
        }).save();
        await user.save();
        res.json({ message: 'Pedido de levantamento recebido. Será processado em breve.' });
    } catch (error) { res.status(500).json({ message: 'Erro ao processar o levantamento.' }); }
});

userRouter.get('/deposit-methods', authMiddleware, async (req, res) => {
    const methods = await DepositMethod.find({ isActive: true });
    res.json(methods);
});

userRouter.post('/deposit', authMiddleware, async (req, res) => {
    const { amount, methodId, userTransactionId } = req.body;
    if (!amount || !methodId || !userTransactionId) return res.status(400).json({ message: 'Valor, método e ID da transação são obrigatórios.' });
    try {
        const depositMethod = await DepositMethod.findById(methodId);
        if (!depositMethod || !depositMethod.isActive) return res.status(404).json({ message: 'Método de depósito não encontrado ou inativo.' });
        await new Transaction({
            user: req.user.id, type: 'DEPOSIT', amount: parseFloat(amount),
            status: 'PENDING', method: depositMethod.name, userTransactionId,
            description: `Pedido de depósito via ${depositMethod.name}`
        }).save();
        res.status(201).json({ message: 'Pedido de depósito enviado com sucesso. Aguarde a aprovação.' });
    } catch (error) { res.status(500).json({ message: 'Erro ao processar o pedido de depósito.' }); }
});

userRouter.put('/change-password', authMiddleware, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Utilizador não encontrado.' });
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) return res.status(400).json({ message: 'A senha atual está incorreta.' });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        res.json({ message: 'Senha de acesso alterada com sucesso.' });
    } catch (error) { res.status(500).json({ message: 'Erro no servidor ao alterar a senha.' }); }
});

userRouter.put('/change-withdrawal-password', authMiddleware, async (req, res) => {
    const { accessPassword, newWithdrawalPassword } = req.body;
    if (!accessPassword || !newWithdrawalPassword) return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Utilizador não encontrado.' });
        const isMatch = await bcrypt.compare(accessPassword, user.password);
        if (!isMatch) return res.status(400).json({ message: 'A senha de acesso (para confirmação) está incorreta.' });
        const salt = await bcrypt.genSalt(10);
        user.withdrawalPassword = await bcrypt.hash(newWithdrawalPassword, salt);
        await user.save();
        res.json({ message: 'Senha de saque alterada com sucesso.' });
    } catch (error) { res.status(500).json({ message: 'Erro no servidor ao alterar a senha de saque.' }); }
});
app.use('/api/user', userRouter);

// ==> ADMIN ROUTES <==
const adminRouter = express.Router();
adminRouter.use(authMiddleware, adminMiddleware); // Apply middleware to all admin routes

adminRouter.get('/users', (req, res) => User.find().select('-password -withdrawalPassword').then(u => res.json(u)));
adminRouter.put('/users/:id/block', (req, res) => User.findByIdAndUpdate(req.params.id, { isBlocked: true }, { new: true }).then(u => res.json(u)));
adminRouter.put('/users/:id/unblock', (req, res) => User.findByIdAndUpdate(req.params.id, { isBlocked: false }, { new: true }).then(u => res.json(u)));

adminRouter.post('/plans', (req, res) => new Plan(req.body).save().then(p => res.status(201).json(p)));
adminRouter.get('/plans', (req, res) => Plan.find().then(p => res.json(p)));
adminRouter.put('/plans/:id', (req, res) => Plan.findByIdAndUpdate(req.params.id, req.body, { new: true }).then(p => res.json(p)));
adminRouter.delete('/plans/:id', (req, res) => Plan.findByIdAndDelete(req.params.id).then(() => res.json({ message: 'Plano removido.' })));

adminRouter.post('/deposit-methods', (req, res) => new DepositMethod(req.body).save().then(m => res.status(201).json(m)));
adminRouter.get('/deposit-methods', (req, res) => DepositMethod.find().then(m => res.json(m)));
adminRouter.put('/deposit-methods/:id', (req, res) => DepositMethod.findByIdAndUpdate(req.params.id, req.body, { new: true }).then(m => res.json(m)));
adminRouter.delete('/deposit-methods/:id', (req, res) => DepositMethod.findByIdAndDelete(req.params.id).then(() => res.json({ message: 'Método de depósito removido.' })));

adminRouter.get('/transactions', (req, res) => Transaction.find().populate('user', 'name email').sort({ createdAt: -1 }).then(t => res.json(t)));
adminRouter.put('/transactions/:id/approve', async (req, res) => {
    try {
        const tx = await Transaction.findById(req.params.id);
        if (!tx || tx.status !== 'PENDING') return res.status(400).json({ message: 'Transação não encontrada ou já processada.' });
        if (tx.type === 'DEPOSIT') {
            const user = await User.findById(tx.user);
            user.balance += tx.amount;
            await user.save();
        }
        tx.status = 'COMPLETED';
        await tx.save();
        res.json(tx);
    } catch (e) { res.status(500).json({ message: 'Erro ao aprovar transação.' }); }
});

adminRouter.put('/transactions/:id/reject', async (req, res) => {
    try {
        const tx = await Transaction.findById(req.params.id);
        if (!tx || tx.status !== 'PENDING') return res.status(400).json({ message: 'Transação não encontrada ou já processada.' });
        if (tx.type === 'WITHDRAWAL') {
            const user = await User.findById(tx.user);
            user.balance += tx.amount;
            await user.save();
        }
        tx.status = 'FAILED';
        await tx.save();
        res.json(tx);
    } catch (e) { res.status(500).json({ message: 'Erro ao rejeitar transação.' }); }
});

app.use('/api/admin', adminRouter);

// -----------------------------------------------------------------------------
// 6. 'CATCH-ALL' ROUTE FOR FRONTEND & SERVER INITIALIZATION
// -----------------------------------------------------------------------------
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Conexão com o MongoDB Atlas estabelecida com sucesso.');
        app.listen(PORT, () => console.log(`Servidor a rodar na porta ${PORT}`));
    })
    .catch(err => {
        console.error('Falha ao conectar com o MongoDB Atlas:', err);
        process.exit(1);
    });
