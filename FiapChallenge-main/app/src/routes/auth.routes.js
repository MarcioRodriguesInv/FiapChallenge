const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// Função para salvar usuários no JSON
const saveUsers = (users) => {
    try {
        const usersData = { users };
        fs.writeFileSync(path.join(__dirname, '../../users.json'), JSON.stringify(usersData, null, 2));
        return true;
    } catch (error) {
        console.error('Erro ao salvar arquivo de usuários:', error);
        return false;
    }
};

// Função para ler usuários do JSON
const getUsers = () => {
    try {
        const usersData = fs.readFileSync(path.join(__dirname, '../../users.json'), 'utf8');
        return JSON.parse(usersData).users;
    } catch (error) {
        console.error('Erro ao ler arquivo de usuários:', error);
        return [];
    }
};

// Função para validar se os dados do dispositivo coincidem
const validateDeviceData = (firstLoginData, currentData) => {
    const criticalFields = ['ip', 'country', 'city', 'visitor_id'];
    const risks = [];

    criticalFields.forEach(field => {
        if (firstLoginData[field] !== currentData[field]) {
            risks.push(`${field} diferente (primeiro: ${firstLoginData[field]}, atual: ${currentData[field]})`);
        }
    });

    return {
        isValid: risks.length === 0,
        risks
    };
};

// Rota de login com validação rigorosa baseada no primeiro login
router.post('/login', (req, res) => {
    const { username, password, deviceData } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: 'Username e password são obrigatórios'
        });
    }

    if (!deviceData) {
        return res.status(400).json({
            success: false,
            message: 'Dados do dispositivo são obrigatórios'
        });
    }

    const users = getUsers();
    const userIndex = users.findIndex(u => 
        (u.username === username || u.email === username) && u.password === password
    );

    if (userIndex === -1) {
        return res.status(401).json({
            success: false,
            message: 'Credenciais inválidas'
        });
    }

    const user = users[userIndex];

    // Se é o primeiro login, salva os dados do dispositivo
    if (!user.firstLoginData) {
        users[userIndex].firstLoginData = {
            ...deviceData,
            registeredAt: new Date().toISOString()
        };
        
        if (saveUsers(users)) {
            return res.json({
                success: true,
                message: 'Primeiro login realizado com sucesso! Dados do dispositivo registrados.',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                },
                firstLogin: true
            });
        } else {
            return res.status(500).json({
                success: false,
                message: 'Erro ao registrar dados do dispositivo'
            });
        }
    }

    // Valida dispositivo baseado no primeiro login
    const validation = validateDeviceData(user.firstLoginData, deviceData);
    
    if (!validation.isValid) {
        // Calcular score de risco, categoria e detalhes
        let riskScore = 0;
        const riskDetails = [];
        validation.risks.forEach(risk => {
            let points = 0;
            let riskCat = 'baixo';
            if (risk.includes('ip diferente')) { points = 20; riskCat = 'médio'; }
            else if (risk.includes('country diferente')) { points = 30; riskCat = 'alto'; }
            else if (risk.includes('city diferente')) { points = 10; riskCat = 'baixo'; }
            else if (risk.includes('visitor_id diferente')) { points = 40; riskCat = 'alto'; }
            else { points = 5; riskCat = 'baixo'; }
            riskScore += points;
            riskDetails.push({ motivo: risk, pontos: points, categoria: riskCat });
        });
        let riskCategory = 'baixo';
        if (riskScore > 70) riskCategory = 'alto';
        else if (riskScore >= 30) riskCategory = 'médio';

        // Log de debug detalhado para o cliente
        const debugInfo = {
            userId: user.id,
            username: user.username,
            firstLoginData: user.firstLoginData,
            currentDeviceData: deviceData,
            risks: validation.risks,
            riskScore,
            riskCategory,
            riskDetails,
            timestamp: new Date().toISOString()
        };

        if (riskScore > 70) {
            return res.status(403).json({
                success: false,
                message: 'Dispositivo não reconhecido! Login bloqueado por segurança.',
                risks: validation.risks,
                securityAlert: true,
                debug: debugInfo
            });
        } else {
            // Permitir login mesmo com diferenças se score <= 70
            return res.json({
                success: true,
                message: 'Login realizado com diferenças no dispositivo, mas dentro do limite de risco permitido.',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                },
                deviceValidated: false,
                debug: debugInfo
            });
        }
    }

    // Login bem-sucedido
    return res.json({
        success: true,
        message: 'Login realizado com sucesso!',
        user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
        },
        deviceValidated: true
    });
});

// Rota de logout
router.post('/logout', (req, res) => {
    res.json({
        success: true,
        message: 'Logout realizado com sucesso!'
    });
});

module.exports = router;
