// =============================================================================
// cBOT - Investment Platform - Final and Complete Backend
// Author: Gemini
// Version: 10.0 (Ready to Run)
// Description: Self-contained backend with all features, including serving
//              frontend files from the root and dynamic page generation.
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

// Serve static files (frontend) from the project's root directory
app.use(express.static(__dirname));

// Environment variable validation
if (!process.env.MONGO_URI || !process.env.JWT_SECRET || !process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.error("FATAL ERROR: Required environment variables are not set. Please configure your .env file locally or in the hosting environment.");
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
// 4. MIDDLEWARES, HELPERS & NODEMAILER CONFIGURATION
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

const generateResponsePage = (title, icon, message, buttonText, buttonLink, isSuccess) => {
    const primaryColor = isSuccess ? '#10B981' : '#e53e3e';
    return `
    <!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>cBOT - ${title}</title><script src="https://code.iconify.design/iconify-icon/2.1.0/iconify-icon.min.js"></script><style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');body{font-family:'Inter',sans-serif;background-color:#111111;color:#f0f0f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1rem;}.container{text-align:center;max-width:450px;background-color:#1a1a1a;border:1px solid #333;border-radius:16px;padding:3rem;box-shadow:0 10px 25px rgba(0,0,0,0.5);}.icon{font-size:4rem;color:${primaryColor};margin-bottom:1.5rem;}h1{font-size:1.8rem;font-weight:700;margin-bottom:1rem;}p{color:#888888;line-height:1.6;margin-bottom:2rem;}.button{display:inline-block;padding:0.8rem 2rem;background-color:${primaryColor};color:#fff;text-decoration:none;border-radius:8px;font-weight:600;transition:background-color .3s;}.button:hover{background-color:${isSuccess?'#0f996b':'#c53030'};}</style></head><body><div class="container"><div class="icon"><iconify-icon icon="${icon}"></iconify-icon></div><h1>${title}</h1><p>${message}</p><a href="${buttonLink}" class="button">${buttonText}</a></div></body></html>`;
};

const generateResetPasswordPage = (token) => {
    return `
    <!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>cBOT - Redefinir Senha</title><script src="https://code.iconify.design/iconify-icon/2.1.0/iconify-icon.min.js"></script><style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');:root{--bg-color:#111;--card-color:#1a1a1a;--border-color:#333;--text-color:#f0f0f0;--text-muted-color:#888;--primary-color:#e53e3e;--primary-hover-color:#c53030;--success-color:#10B981}*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',sans-serif;background-color:var(--bg-color);color:var(--text-color);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}.container{width:100%;max-width:420px;background-color:var(--card-color);border:1px solid var(--border-color);border-radius:16px;padding:2.5rem;box-shadow:0 10px 25px rgba(0,0,0,.5)}.header{text-align:center;margin-bottom:2rem}.header iconify-icon{font-size:3rem;color:var(--primary-color);margin-bottom:1rem}h1{font-size:1.8rem;font-weight:700}.header p{color:var(--text-muted-color);margin-top:.5rem;font-size:.9rem;line-height:1.5}.form{display:flex;flex-direction:column;gap:1.25rem}.input-group label{font-size:.875rem;font-weight:500;color:var(--text-muted-color);margin-bottom:.5rem;display:block}.input-field{width:100%;background-color:#2b2b2b;border:1px solid var(--border-color);border-radius:8px;padding:.8rem 1rem;color:var(--text-color);font-size:1rem;transition:all .3s}.input-field:focus{outline:none;border-color:var(--primary-color);box-shadow:0 0 0 3px rgba(229,62,62,.3)}.submit-button{display:flex;align-items:center;justify-content:center;width:100%;padding:.8rem 1rem;background-color:var(--primary-color);color:#fff;font-size:1rem;font-weight:600;border:none;border-radius:8px;cursor:pointer;transition:background-color .3s;margin-top:.5rem}.submit-button:disabled{background-color:#555;cursor:not-allowed}.spinner{display:none;width:20px;height:20px;border:2px solid rgba(255,255,255,.3);border-radius:50%;border-top-color:#fff;animation:spin 1s ease-in-out infinite}@keyframes spin{to{transform:rotate(360deg)}}.feedback-message{display:none;padding:.8rem;border-radius:8px;text-align:center;font-weight:500;margin-top:1rem;font-size:.9rem}.feedback-message.success{background-color:rgba(16,185,129,.1);color:var(--success-color)}.feedback-message.error{background-color:rgba(229,62,62,.1);color:var(--primary-color)}.login-link{text-align:center;margin-top:1.5rem;display:none}.login-link a{color:var(--primary-color);font-weight:600;text-decoration:none}</style></head><body><div class="container"><div class="header"><iconify-icon icon="mdi:key-change-outline"></iconify-icon><h1>Defina a sua Nova Senha</h1><p>Escolha uma senha forte e segura que não tenha usado anteriormente.</p></div><form id="resetPasswordForm" class="form"><div class="input-group"><label for="password">Nova Senha</label><input type="password" id="password" class="input-field" required minlength="6"></div><div class="input-group"><label for="confirmPassword">Confirmar Nova Senha</label><input type="password" id="confirmPassword" class="input-field" required minlength="6"></div><button type="submit" class="submit-button" id="submitButton"><span id="buttonText">Redefinir Senha</span><div class="spinner" id="buttonSpinner"></div></button></form><div id="feedbackMessage" class="feedback-message"></div><div class="login-link" id="loginLinkContainer"><a href="/login.html">Ir para o Login</a></div></div><script>document.addEventListener('DOMContentLoaded',()=>{const e=document.getElementById("resetPasswordForm"),t=document.getElementById("submitButton"),s=document.getElementById("buttonText"),o=document.getElementById("buttonSpinner"),n=document.getElementById("feedbackMessage"),i=document.getElementById("loginLinkContainer"),a=new URLSearchParams(window.location.search).get("token");a||(e.style.display="none",r("Token de recuperação não encontrado.","error"));const d=s=>{t.disabled=s,s.style.display=s?"none":"block",o.style.display=s?"block":"none"},r=(e,t)=>{n.textContent=e,n.className=`feedback-message ${t}`,n.style.display="block"};e.addEventListener("submit",async t=>{t.preventDefault(),n.style.display="none";const s=document.getElementById("password").value,o=document.getElementById("confirmPassword").value;if(s!==o)return void r("As senhas não coincidem.","error");d(!0);try{const t=await fetch(`/api/auth/reset-password/${a}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:s})}),o=await t.json();t.ok?(r(o.message,"success"),e.style.display="none",i.style.display="block"):r(o.message||"Ocorreu um erro.","error")}catch(e){r("Não foi possível conectar ao servidor.","error")}finally{d(!1)}})})</script></body></html>`;
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
        const user = new User({ name, email, password: await bcrypt.hash(password, salt), withdrawalPassword: await bcrypt.hash(withdrawalPassword, salt), verificationToken: uuidv4() });
        await user.save();
        const verificationUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${user.verificationToken}`;
        await transporter.sendMail({ to: user.email, from: `"Plataforma cBOT" <${process.env.GMAIL_USER}>`, subject: 'Verifique a sua conta cBOT', html: `<p>Bem-vindo à cBOT! Por favor, clique no link abaixo para verificar a sua conta:</p><a href="${verificationUrl}">${verificationUrl}</a>` });
        res.status(201).json({ message: 'Registo bem-sucedido! Um e-mail de verificação foi enviado.' });
    } catch (error) { res.status(500).json({ message: 'Erro no servidor durante o registo.' }); }
});

authRouter.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Por favor, forneça e-mail e senha.' });
    try {
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Credenciais inválidas.' });
        if (!user.isVerified) return res.status(403).json({ message: 'A sua conta não foi verificada.' });
        if (user.isBlocked) return res.status(403).json({ message: 'A sua conta está bloqueada.' });
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
        user.resetPasswordExpires = Date.now() + 3600000;
        await user.save();
        const resetURL = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}`;
        await transporter.sendMail({ to: user.email, from: `"Plataforma cBOT" <${process.env.GMAIL_USER}>`, subject: 'Recuperação de Senha cBOT', html: `<p>Solicitou a redefinição da sua senha. Clique no link para prosseguir:</p><a href="${resetURL}">${resetURL}</a>` });
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
userRouter.use(authMiddleware);

userRouter.get('/dashboard', async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -withdrawalPassword');
        const activeBots = await Bot.find({ user: req.user.id, isCompleted: false }).populate('plan');
        const transactions = await Transaction.find({ user: req.user.id }).sort({ createdAt: -1 }).limit(10);
        res.json({ user, activeBots, transactions });
    } catch (error) { res.status(500).json({ message: 'Erro ao buscar dados do dashboard.' }); }
});

userRouter.get('/transactions', async (req, res) => {
    try {
        const transactions = await Transaction.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.json(transactions);
    } catch (error) { res.status(500).json({ message: 'Erro ao buscar histórico de transações.' }); }
});

userRouter.post('/invest', async (req, res) => {
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

userRouter.post('/withdraw', async (req, res) => {
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
        res.json({ message: 'Pedido de levantamento recebido.' });
    } catch (error) { res.status(500).json({ message: 'Erro ao processar o levantamento.' }); }
});

userRouter.get('/deposit-methods', async (req, res) => {
    try {
        const methods = await DepositMethod.find({ isActive: true });
        res.json(methods);
    } catch(error) { res.status(500).json({ message: 'Erro ao buscar métodos de depósito.'}) }
});

userRouter.post('/deposit', async (req, res) => {
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
        res.status(201).json({ message: 'Pedido de depósito enviado com sucesso.' });
    } catch (error) { res.status(500).json({ message: 'Erro ao processar o pedido de depósito.' }); }
});

userRouter.put('/change-password', async (req, res) => {
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

userRouter.put('/change-withdrawal-password', async (req, res) => {
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
adminRouter.use(authMiddleware, adminMiddleware);

adminRouter.get('/users', (req, res) => User.find().select('-password -withdrawalPassword').then(u => res.json(u)).catch(e => res.status(500).json(e)));
adminRouter.put('/users/:id/block', (req, res) => User.findByIdAndUpdate(req.params.id, { isBlocked: true }, { new: true }).then(u => res.json(u)).catch(e => res.status(500).json(e)));
adminRouter.put('/users/:id/unblock', (req, res) => User.findByIdAndUpdate(req.params.id, { isBlocked: false }, { new: true }).then(u => res.json(u)).catch(e => res.status(500).json(e)));
adminRouter.post('/plans', (req, res) => new Plan(req.body).save().then(p => res.status(201).json(p)).catch(e => res.status(500).json(e)));
adminRouter.get('/plans', (req, res) => Plan.find().then(p => res.json(p)).catch(e => res.status(500).json(e)));
adminRouter.put('/plans/:id', (req, res) => Plan.findByIdAndUpdate(req.params.id, req.body, { new: true }).then(p => res.json(p)).catch(e => res.status(500).json(e)));
adminRouter.delete('/plans/:id', (req, res) => Plan.findByIdAndDelete(req.params.id).then(() => res.json({ message: 'Plano removido.' })).catch(e => res.status(500).json(e)));
adminRouter.post('/deposit-methods', (req, res) => new DepositMethod(req.body).save().then(m => res.status(201).json(m)).catch(e => res.status(500).json(e)));
adminRouter.get('/deposit-methods', (req, res) => DepositMethod.find().then(m => res.json(m)).catch(e => res.status(500).json(e)));
adminRouter.put('/deposit-methods/:id', (req, res) => DepositMethod.findByIdAndUpdate(req.params.id, req.body, { new: true }).then(m => res.json(m)).catch(e => res.status(500).json(e)));
adminRouter.delete('/deposit-methods/:id', (req, res) => DepositMethod.findByIdAndDelete(req.params.id).then(() => res.json({ message: 'Método de depósito removido.' })).catch(e => res.status(500).json(e)));
adminRouter.get('/transactions', (req, res) => Transaction.find().populate('user', 'name email').sort({ createdAt: -1 }).then(t => res.json(t)).catch(e => res.status(500).json(e)));
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
// 6. DYNAMIC PAGE SERVING & 'CATCH-ALL' ROUTE
// -----------------------------------------------------------------------------

app.get('/verify-email', async (req, res) => {
    try {
        const user = await User.findOne({ verificationToken: req.query.token });
        if (!user) {
            const html = generateResponsePage('Verificação Falhou', 'mdi:alert-circle-outline', 'Este token de verificação é inválido ou já foi utilizado.', 'Ir para a Página Inicial', '/', false);
            return res.status(400).send(html);
        }
        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();
        const html = generateResponsePage('E-mail Verificado!', 'mdi:check-circle-outline', 'A sua conta foi verificada com sucesso. Já pode fechar esta janela e fazer login.', 'Ir para o Login', '/login.html', true);
        res.send(html);
    } catch (error) {
        const html = generateResponsePage('Erro no Servidor', 'mdi:server-network-off', 'Ocorreu um erro inesperado. Tente novamente mais tarde.', 'Ir para a Página Inicial', '/', false);
        res.status(500).send(html);
    }
});

app.get('/reset-password.html', (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.status(400).send(generateResponsePage('Token Inválido', 'mdi:alert-circle-outline', 'O link de recuperação está incompleto.', 'Ir para a Página Inicial', '/', false));
    }
    const html = generateResetPasswordPage(token);
    res.send(html);
});

// 'CATCH-ALL' ROUTE: Must be the last GET route
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'), (err) => {
        if (err) {
            res.status(404).send("Página não encontrada.");
        }
    });
});

// -----------------------------------------------------------------------------
// 7. SERVER INITIALIZATION
// -----------------------------------------------------------------------------
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
