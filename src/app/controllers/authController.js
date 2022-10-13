const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const mailer = require('../../modules/mailer')

const authConfig = require('../../config/auth.json'); 

const User = require('../models/user');

const router = express.Router();

function generateToken(params = {}) {
    return jwt.sign(params, authConfig.secret, {
        expiresIn: 86400,
    })
}


// Rota de Registro:
router.post('/register', async (req, res) => {

    //Pegando o e-mail digitado pelo usuário pra checar se já foi usado em outro registro:
    const { email } = req.body;

    try {
        if (await User.findOne({ email }))
            return res.status(400).send({ error: 'User already exists' })

        const user = await User.create(req.body);

        user.password = undefined;

        //Retornando o usuário e token depois do registro:
        return res.send({
            user,
            token: generateToken({ id: user.id }),
        });
    } catch (err) {
        return res.status(400).send({ erro: 'Registration failed ' });
    }
});


// Rota de Autenticação:
router.post('/authenticate', async (req, res) => {
    const { email, password } = req.body;

    // o select+password existe aqui pra autenticação ter acesso ao password, já que no nosso scheme de usuário o password estava com select false (pra não retornar)
    const user = await User.findOne({ email }).select('+password');

    // verificando se o usuário não existe:
    if (!user)
        return res.status(400).send({ error: 'User not found' });

    // verificando se a senha que ele digitou é igual a senha que está no banco de dados, importando o módulo do bcrypt:
    if (!await bcrypt.compare(password, user.password))
        return res.status(400).send({ error: "Invalid password" })

    user.password = undefined;

    // gerando nosso token:
    const token = jwt.sign({ id: user.id }, authConfig.secret, {
        expiresIn: 86400,
    })


    res.send({
        user,
        token: generateToken({ id: user.id }),
    })

});


// Rota de Esqueci minha Senha:
router.post('/forgot_password', async (req, res) => {
    const { email } = req.body;

    try{
        const user = await User.findOne({ email })

        if (!user)
            return res.status(400).send({ error: 'User not found' })

        const token = crypto.randomBytes(20).toString('hex');

        // Data e tempo de expiração (1h a mais do momento atual)
        const now = new Date();
        now.setHours(now.getHours() + 1);

        await User.findByIdAndUpdate(user.id, {
            '$set': {
                passwordResetToken: token,
                passwordResetExpires: now
            }
        });

        mailer.sendMail({
            to: email,
            from: 'matheus.almn@gmail.com',
            template: 'forgot_password',
            context: { token },
            // Na linha acima, é necessário passar para o mailer a variável utilizada no template!
        }, (err) => {
            if (err)
                return res.status(400).send({ error: 'Cannot send forgot password email'})
                console.log(err)

            return res.send(200)
        })

        console.log(token, now);

    } catch (err) {
        console.log(err)
        res.status(400).send({ error: 'Error on forgot password, try again' })
    }
})


// Rota de resetar a senha:
router.post('/reset_password', async (req, res) => {
    const { email, token, password } = req.body;

    try {
        const user = await User.findOne({ email })
        .select('+passwordResetToken passwordResetExpires');
        //Na linha abaixo, verificando se o usuário existe:
        if (!user)
        return res.status(400).send({ error: 'User not found' });
        //Na linha abaixo, verificando se o token enviado pela requisição é o mesmo daquele que consta gravado no model do user:
        if (token !== user.passwordResetToken)
            return res.status(400).send({ error: 'Token invalid' });
        
        const now = new Date();
        //Na linha abaixo, verificando se o token gravado no model do user (+1h do momento que foi gerado) é menor do que o tempo de agora. Ou seja, descobrindo se já expirou:
        if (now > user.passwordResetExpires)
            return res.status(400).send({ error: 'Token expired, generate a new one'})
            
    // Como no model de user já temos a parte de gerar o hash pelo Mongoose, usando o evento da ln 34 antes de salvar, não precisa fazer nenhum tipo de encriptação aqui:
    user.password = password;
    await user.save()

    res.send();    
    } catch (err) {
        res.status(400).send({ error: 'Cannot reset password, try again'});
    }
})



// Recuperando o "app" que foi passado no Step A e retornando app.use para definir uma rota raiz para tudo feito aqui
module.exports = app => app.use('/auth', router);