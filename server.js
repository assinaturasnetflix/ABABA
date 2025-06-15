// =============================================================================
// Satang - Plataforma de Investimentos - Backend Completo
// Autor: Gemini
// Descrição: Backend funcional e seguro para uma plataforma de investimentos.
// Tecnologias: Node.js, Express, MongoDB (Mongoose), JWT, Bcrypt, Nodemailer.
// Tudo implementado em um único arquivo (server.js).
// =============================================================================

// -----------------------------------------------------------------------------
// 1. IMPORTAÇÃO DE DEPENDÊNCIAS
// -----------------------------------------------------------------------------
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const cors = require('cors'); // Adicionado para permitir requisições de diferentes origens (frontend)

// -----------------------------------------------------------------------------
// 2. CONFIGURAÇÃO INICIAL
// -----------------------------------------------------------------------------
dotenv.config(); // Carrega variáveis de ambiente do arquivo .env

const app = express();
app.use(express.json()); // Middleware para parsear o corpo das requisições como JSON
app.use(cors()); // Middleware para habilitar CORS

// Validação inicial das variáveis de ambiente essenciais
if (!process.env.MONGO_URI || !process.env.JWT_SECRET || !process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.error("ERRO: Variáveis de ambiente (MONGO_URI, JWT_SECRET, GMAIL_USER, GMAIL_PASS) são obrigatórias. Configure o arquivo .env");
    process.exit(1); // Encerra o processo se as variáveis não estiverem definidas
}

// -----------------------------------------------------------------------------
// 3. MODELOS DO MONGOOSE (SCHEMAS)
// -----------------------------------------------------------------------------

// Esquema do Usuário (User)
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
    activePlan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', default: null },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Esquema do Plano de Investimento (Plan)
const PlanSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    minAmount: { type: Number, required: true },
    durationDays: { type: Number, required: true },
    roiPercentage: { type: Number, required: true }, // Retorno sobre o Investimento (em %)
    isActive: { type: Boolean, default: true },
});

const Plan = mongoose.model('Plan', PlanSchema);

// Esquema do Bot (Investimento Ativo)
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

// Esquema do Banner
const BannerSchema = new mongoose.Schema({
    title: { type: String, required: true },
    imageUrl: { type: String, required: true },
    link: { type: String, default: '#' },
    isActive: { type: Boolean, default: true }
});

const Banner = mongoose.model('Banner', BannerSchema);

// Esquema de Transações
const TransactionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['DEPOSIT', 'WITHDRAWAL', 'INVESTMENT', 'PROFIT'], required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['COMPLETED', 'PENDING', 'FAILED'], default: 'COMPLETED' },
    description: { type: String },
    createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', TransactionSchema);

// -----------------------------------------------------------------------------
// 4. CONFIGURAÇÃO DO NODEMAILER (GMAIL)
// -----------------------------------------------------------------------------
// IMPORTANTE: Para usar o Gmail, você precisa gerar uma "App Password"
// 1. Vá para a sua Conta Google.
// 2. Selecione "Segurança".
// 3. Em "Como você faz login no Google", selecione "Senhas de app".
// 4. Gere uma nova senha, dê um nome (ex: Satang Backend) e copie a senha gerada.
// 5. Cole essa senha na variável GMAIL_PASS no seu arquivo .env
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
    },
});

// -----------------------------------------------------------------------------
// 5. MIDDLEWARES DE AUTENTICAÇÃO E AUTORIZAÇÃO
// -----------------------------------------------------------------------------

// Middleware para verificar o token JWT (autenticação de usuário)
const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
        return res.status(401).json({ message: 'Acesso negado. Nenhum token fornecido.' });
    }

    const token = authHeader.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ message: 'Acesso negado. Token mal formatado.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Adiciona os dados do usuário (ex: id, isAdmin) ao objeto da requisição
        next();
    } catch (error) {
        res.status(400).json({ message: 'Token inválido.' });
    }
};

// Middleware para verificar se o usuário é um administrador
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
// 6. ROTAS DA API
// -----------------------------------------------------------------------------

// ==> ROTAS DE AUTENTICAÇÃO <==
const authRouter = express.Router();

// [POST] /api/auth/register - Registrar um novo usuário
authRouter.post('/register', async (req, res) => {
    const { name, email, password, withdrawalPassword } = req.body;

    if (!name || !email || !password || !withdrawalPassword) {
        return res.status(400).json({ message: 'Por favor, preencha todos os campos.' });
    }

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'Usuário já cadastrado com este e-mail.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const hashedWithdrawalPassword = await bcrypt.hash(withdrawalPassword, salt);
        const verificationToken = uuidv4();

        user = new User({
            name,
            email,
            password: hashedPassword,
            withdrawalPassword: hashedWithdrawalPassword,
            verificationToken,
        });

        await user.save();
        
        // Enviar e-mail de verificação
        // OBS: Substitua 'localhost:3000' pelo seu domínio de frontend
        const verificationUrl = `http://localhost:3000/api/auth/verify-email?token=${verificationToken}`;
        const mailOptions = {
            from: `"Satang Plataforma" <${process.env.GMAIL_USER}>`,
            to: user.email,
            subject: 'Verifique sua conta na Satang',
            html: `
                <h1>Bem-vindo à Satang!</h1>
                <p>Obrigado por se registrar. Por favor, clique no link abaixo para verificar sua conta:</p>
                <a href="${verificationUrl}" target="_blank">Verificar E-mail</a>
                <p>Se você não solicitou este registro, por favor, ignore este e-mail.</p>
            `,
        };

        await transporter.sendMail(mailOptions);

        res.status(201).json({ message: 'Registro bem-sucedido! Um e-mail de verificação foi enviado.' });

    } catch (error) {
        console.error("Erro no registro:", error);
        res.status(500).json({ message: 'Erro no servidor durante o registro.' });
    }
});


// [GET] /api/auth/verify-email - Verificar o e-mail do usuário
authRouter.get('/verify-email', async (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.status(400).send('<h1>Token de verificação inválido ou ausente.</h1>');
    }

    try {
        const user = await User.findOne({ verificationToken: token });
        if (!user) {
            return res.status(400).send('<h1>Token de verificação inválido ou expirado.</h1>');
        }

        user.isVerified = true;
        user.verificationToken = undefined; // Limpa o token após o uso
        await user.save();

        res.send('<h1>E-mail verificado com sucesso! Agora você pode fazer login.</h1>');
    } catch (error) {
        console.error("Erro na verificação de e-mail:", error);
        res.status(500).send('<h1>Erro no servidor ao verificar o e-mail.</h1>');
    }
});

// [POST] /api/auth/login - Fazer login
authRouter.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, forneça e-mail e senha.' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Credenciais inválidas.' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Sua conta não foi verificada. Por favor, verifique seu e-mail.' });
        }
        
        if (user.isBlocked) {
            return res.status(403).json({ message: 'Sua conta está bloqueada. Entre em contato com o suporte.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciais inválidas.' });
        }

        const payload = {
            id: user.id,
            name: user.name,
            isAdmin: user.isAdmin,
        };

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                isAdmin: user.isAdmin
            }
        });

    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ message: 'Erro no servidor durante o login.' });
    }
});


app.use('/api/auth', authRouter);


// ==> ROTAS DO USUÁRIO <==
const userRouter = express.Router();

// [GET] /api/user/dashboard - Obter dados do dashboard do usuário
userRouter.get('/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -withdrawalPassword');
        const activeBots = await Bot.find({ user: req.user.id, isCompleted: false }).populate('plan');
        const transactions = await Transaction.find({ user: req.user.id }).sort({ createdAt: -1 }).limit(10);
        
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        
        res.json({ user, activeBots, transactions });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar dados do dashboard.' });
    }
});

// [POST] /api/user/invest - Ativar um plano de investimento
userRouter.post('/invest', authMiddleware, async (req, res) => {
    const { planId, amount } = req.body;
    const userId = req.user.id;

    if (!planId || !amount) {
        return res.status(400).json({ message: 'ID do plano e valor são obrigatórios.' });
    }

    try {
        const plan = await Plan.findById(planId);
        const user = await User.findById(userId);

        if (!plan || !plan.isActive) {
            return res.status(404).json({ message: 'Plano não encontrado ou inativo.' });
        }

        if (amount < plan.minAmount) {
            return res.status(400).json({ message: `O valor do investimento deve ser de no mínimo ${plan.minAmount}.` });
        }

        if (user.balance < amount) {
            return res.status(400).json({ message: 'Saldo insuficiente.' });
        }

        // Debitar o saldo do usuário
        user.balance -= amount;
        
        // Criar o Bot (investimento ativo)
        const startDate = new Date();
        const endDate = new Date(startDate);
        endDate.setDate(startDate.getDate() + plan.durationDays);
        const expectedProfit = amount * (plan.roiPercentage / 100);

        const newBot = new Bot({
            user: userId,
            plan: planId,
            investedAmount: amount,
            expectedProfit,
            endDate
        });

        // Registrar a transação
        const newTransaction = new Transaction({
            user: userId,
            type: 'INVESTMENT',
            amount: amount,
            description: `Investimento no plano ${plan.name}`
        });

        await user.save();
        await newBot.save();
        await newTransaction.save();

        res.status(201).json({ message: 'Investimento realizado com sucesso!', bot: newBot });

    } catch (error) {
        console.error("Erro ao investir:", error);
        res.status(500).json({ message: 'Erro no servidor ao processar o investimento.' });
    }
});


// [POST] /api/user/withdraw - Solicitar um saque
userRouter.post('/withdraw', authMiddleware, async (req, res) => {
    const { amount, withdrawalPassword } = req.body;
    const userId = req.user.id;

    if (!amount || !withdrawalPassword) {
        return res.status(400).json({ message: 'Valor do saque e senha de saque são obrigatórios.' });
    }
    
    if(amount <= 0) {
        return res.status(400).json({ message: 'O valor do saque deve ser positivo.' });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        const isPasswordMatch = await bcrypt.compare(withdrawalPassword, user.withdrawalPassword);
        if (!isPasswordMatch) {
            return res.status(400).json({ message: 'Senha de saque incorreta.' });
        }

        if (user.balance < amount) {
            return res.status(400).json({ message: 'Saldo insuficiente para realizar o saque.' });
        }

        // Lógica de saque (aqui poderia integrar com um gateway de pagamento)
        user.balance -= amount;

        const newTransaction = new Transaction({
            user: userId,
            type: 'WITHDRAWAL',
            amount: amount,
            status: 'PENDING', // Saques podem precisar de aprovação manual
            description: `Solicitação de saque no valor de ${amount}`
        });

        await user.save();
        await newTransaction.save();
        
        // Opcional: Enviar e-mail de notificação de saque para o admin e usuário

        res.json({ message: 'Solicitação de saque recebida e em processamento.' });

    } catch (error) {
        console.error("Erro ao solicitar saque:", error);
        res.status(500).json({ message: 'Erro no servidor ao processar o saque.' });
    }
});


app.use('/api/user', userRouter);


// ==> ROTAS DO ADMIN <==
const adminRouter = express.Router();

// [GET] /api/admin/dashboard - Estatísticas para o painel admin
adminRouter.get('/dashboard', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalInvestments = await Bot.countDocuments();
        const totalInvestedAmount = await Bot.aggregate([
            { $group: { _id: null, total: { $sum: '$investedAmount' } } }
        ]);
        const pendingWithdrawals = await Transaction.countDocuments({ type: 'WITHDRAWAL', status: 'PENDING' });

        res.json({
            totalUsers,
            totalInvestments,
            totalInvested: totalInvestedAmount.length > 0 ? totalInvestedAmount[0].total : 0,
            pendingWithdrawals
        });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar estatísticas do admin.' });
    }
});

// --- CRUD de Usuários ---
adminRouter.get('/users', (req, res) => User.find().select('-password -withdrawalPassword').then(users => res.json(users)));
adminRouter.put('/users/:id/balance', async (req, res) => {
    const { amount, type } = req.body; // type: 'ADD' ou 'REMOVE'
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: 'Usuário não encontrado.'});
        
        const newBalance = type === 'ADD' ? user.balance + amount : user.balance - amount;
        if(newBalance < 0) return res.status(400).json({ message: 'Saldo não pode ser negativo.'});
        
        user.balance = newBalance;
        await user.save();
        
        // Log transaction
        await new Transaction({
            user: user.id,
            type: 'DEPOSIT', // Considera um ajuste manual como depósito
            amount: amount,
            status: 'COMPLETED',
            description: `Ajuste manual de saldo pelo administrador. Tipo: ${type}`
        }).save();
        
        res.json(user);
    } catch(e) { res.status(500).json({message: 'Erro ao atualizar saldo.'}) }
});
adminRouter.put('/users/:id/block', (req, res) => User.findByIdAndUpdate(req.params.id, { isBlocked: true }, { new: true }).then(user => res.json(user)));
adminRouter.put('/users/:id/unblock', (req, res) => User.findByIdAndUpdate(req.params.id, { isBlocked: false }, { new: true }).then(user => res.json(user)));
adminRouter.delete('/users/:id', async (req, res) => {
    try {
        // Lógica mais complexa pode ser necessária (ex: anonimizar dados em vez de deletar)
        await User.findByIdAndDelete(req.params.id);
        await Bot.deleteMany({ user: req.params.id });
        await Transaction.deleteMany({ user: req.params.id });
        res.json({ message: 'Usuário e dados associados removidos.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao remover usuário.' });
    }
});

// --- CRUD de Planos de Investimento ---
adminRouter.post('/plans', (req, res) => new Plan(req.body).save().then(plan => res.status(201).json(plan)));
adminRouter.get('/plans', (req, res) => Plan.find().then(plans => res.json(plans)));
adminRouter.put('/plans/:id', (req, res) => Plan.findByIdAndUpdate(req.params.id, req.body, { new: true }).then(plan => res.json(plan)));
adminRouter.delete('/plans/:id', (req, res) => Plan.findByIdAndDelete(req.params.id).then(() => res.json({ message: 'Plano removido.' })));


// --- CRUD de Banners ---
adminRouter.post('/banners', (req, res) => new Banner(req.body).save().then(banner => res.status(201).json(banner)));
adminRouter.get('/banners', (req, res) => Banner.find().then(banners => res.json(banners)));
adminRouter.put('/banners/:id', (req, res) => Banner.findByIdAndUpdate(req.params.id, req.body, { new: true }).then(banner => res.json(banner)));
adminRouter.delete('/banners/:id', (req, res) => Banner.findByIdAndDelete(req.params.id).then(() => res.json({ message: 'Banner removido.' })));

// --- Gestão de Bots e Transações ---
adminRouter.get('/bots', (req, res) => Bot.find().populate('user', 'name email').populate('plan', 'name').then(bots => res.json(bots)));
adminRouter.get('/transactions', (req, res) => Transaction.find().populate('user', 'name email').sort({ createdAt: -1 }).then(transactions => res.json(transactions)));
adminRouter.put('/transactions/:id/approve', async (req, res) => {
    try {
        const tx = await Transaction.findById(req.params.id);
        if (tx && tx.type === 'WITHDRAWAL' && tx.status === 'PENDING') {
            tx.status = 'COMPLETED';
            await tx.save();
            res.json(tx);
        } else {
            res.status(400).json({ message: 'Transação não é um saque pendente.'});
        }
    } catch(e) { res.status(500).json({message: 'Erro ao aprovar saque.'}); }
});
adminRouter.put('/transactions/:id/reject', async (req, res) => {
    try {
        const tx = await Transaction.findById(req.params.id);
        if (tx && tx.type === 'WITHDRAWAL' && tx.status === 'PENDING') {
            const user = await User.findById(tx.user);
            user.balance += tx.amount; // Devolve o valor ao saldo do usuário
            tx.status = 'FAILED';
            await user.save();
            await tx.save();
            res.json(tx);
        } else {
            res.status(400).json({ message: 'Transação não é um saque pendente.'});
        }
    } catch(e) { res.status(500).json({message: 'Erro ao rejeitar saque.'}); }
});


// Aplicar middlewares de autenticação e admin para todas as rotas de admin
app.use('/api/admin', authMiddleware, adminMiddleware, adminRouter);


// ==> ROTAS PÚBLICAS (EX: Para o site) <==
const publicRouter = express.Router();
publicRouter.get('/plans', (req, res) => Plan.find({ isActive: true }).then(plans => res.json(plans)));
publicRouter.get('/banners', (req, res) => Banner.find({ isActive: true }).then(banners => res.json(banners)));
app.use('/api/public', publicRouter);

// -----------------------------------------------------------------------------
// 7. MIDDLEWARE DE ERRO GENÉRICO
// -----------------------------------------------------------------------------
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Algo deu errado no servidor!');
});

// -----------------------------------------------------------------------------
// 8. CONEXÃO COM O BANCO DE DADOS E INICIALIZAÇÃO DO SERVIDOR
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;

// IMPORTANTE:
// A string de conexão do MongoDB Atlas deve ser colocada no arquivo .env
// Exemplo no arquivo .env:
// MONGO_URI=mongodb+srv://<username>:<password>@<cluster-url>/<database-name>?retryWrites=true&w=majority
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Conexão com o MongoDB Atlas estabelecida com sucesso.');
    app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
}).catch(err => {
    console.error('Falha ao conectar com o MongoDB Atlas:', err);
    process.exit(1);
});
