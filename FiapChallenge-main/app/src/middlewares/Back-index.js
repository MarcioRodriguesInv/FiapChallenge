const express = require('express');
const cors = require('cors');
const fs = require('fs'); // Pra ler o users.json
const { generateDeviceFingerprint } = require('./deviceValidation'); // Usa o módulo do Gustavinho
const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Rota inicial (só pra testar)
app.get('/', (req, res) => {
    res.send('Olá! Backend funcionando!');
});

// Rota /identity/verify
app.post('/identity/verify', (req, res) => {
    // Recebe os dados enviados pelo front
    const data = req.body;
    console.log('Dados recebidos:', data);

    try {
        // Lê o users.json
        const usersData = JSON.parse(fs.readFileSync('users.json', 'utf8'));
        const user = usersData.users.find(u => u.username === data.username);

        let action = 'deny';
        let score = 0;
        let reason = 'Usuário não encontrado';

        if (user && user.firstLoginData) {
            const savedIp = user.firstLoginData.ip;
            // Gera fingerprint do dispositivo atual
            const currentFingerprint = generateDeviceFingerprint({
                visitor_id: data.visitorId || 'unknown',
                user_agent: data.userAgent || 'unknown',
                language: data.language || 'unknown',
                timezone: data.timezone || 'unknown'
            });
            // Gera fingerprint salvo (baseado no firstLoginData)
            const savedFingerprintData = {
                visitor_id: user.firstLoginData.visitor_id || 'unknown',
                user_agent: user.firstLoginData.user_agent || 'unknown',
                language: user.firstLoginData.language || 'unknown',
                timezone: user.firstLoginData.timezone || 'unknown'
            };
            const savedFingerprint = generateDeviceFingerprint(savedFingerprintData);

            if (savedIp === data.ip) {
                if (savedFingerprint === currentFingerprint) {
                    const timeOnPage = data.timeOnPage || 0;
                    if (timeOnPage >= 30) {
                        action = 'allow';
                        score = 100;
                        reason = 'Usuário, IP, dispositivo e tempo OK';
                    } else {
                        action = 'review';
                        score = 70;
                        reason = 'Usuário, IP e dispositivo OK, mas tempo baixo';
                    }
                } else {
                    action = 'allow';
                    score = 80;
                    reason = 'Usuário e IP encontrados, mas dispositivo diferente';
                }
            } else {
                action = 'review';
                score = 50;
                reason = 'Usuário encontrado, mas IP diferente';
            }
        } else if (user) {
            action = 'review';
            score = 50;
            reason = 'Usuário encontrado, mas sem dados de login salvos';
        }

        res.json({
            action: action,
            score: score,
            reason: reason
        });
    } catch (error) {
        console.error('Erro ao processar requisição:', error);
        res.status(500).json({
            action: 'deny',
            score: 0,
            reason: 'Erro interno no servidor'
        });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});