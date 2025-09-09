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
        return res.status(403).json({
            success: false,
            message: 'Dispositivo não reconhecido! Login bloqueado por segurança.',
            risks: validation.risks,
            securityAlert: true
        });
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
