const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Função para calcular similaridade entre duas localizações
const calculateLocationSimilarity = (loc1, loc2) => {
    if (!loc1 || !loc2) return 0;
    
    // Verifica país
    if (loc1.country_code !== loc2.country_code) return 0.1;
    
    // Verifica cidade
    if (loc1.city !== loc2.city) return 0.3;
    
    // Calcula distância se as coordenadas estiverem disponíveis
    if (loc1.latitude && loc1.longitude && loc2.latitude && loc2.longitude) {
        const distance = calculateDistance(
            loc1.latitude, loc1.longitude,
            loc2.latitude, loc2.longitude
        );
        
        // Considera similar se estiver dentro de 50km
        if (distance <= 50) return 1.0;
        if (distance <= 100) return 0.8;
        if (distance <= 200) return 0.6;
        return 0.2;
    }
    
    return 1.0; // Mesma cidade
};

// Função para calcular distância entre coordenadas (fórmula de Haversine)
const calculateDistance = (lat1, lon1, lat2, lon2) => {
    const R = 6371; // Raio da Terra em km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
};

// Função para gerar fingerprint do dispositivo
const generateDeviceFingerprint = (deviceData) => {
    const fingerprintString = `${deviceData.visitor_id || 'unknown'}_${deviceData.user_agent || 'unknown'}_${deviceData.language || 'unknown'}_${deviceData.timezone || 'unknown'}`;
    return crypto.createHash('sha256').update(fingerprintString).digest('hex');
};

// Função para analisar risco do login
const analyzeLoginRisk = (currentDevice, registeredDevices, securityProfile) => {
    const risks = [];
    let riskScore = 0;

    // Parâmetros adicionais esperados em currentDevice
    // currentDevice.responseTimeMs, currentDevice.passwordScore, currentDevice.actionType

    if (registeredDevices.length === 0) {
        return {
            riskLevel: 'low',
            riskScore: 0,
            risks: ['first_login'],
            action: 'register_device'
        };
    }

    // Device fingerprint
    const deviceFingerprint = generateDeviceFingerprint(currentDevice);
    const knownDevice = registeredDevices.find(device => device.fingerprint === deviceFingerprint);

    // Verificação de fingerprint similar
    let fingerprintSimilarity = 0;
    if (!knownDevice) {
        fingerprintSimilarity = registeredDevices.reduce((max, device) => {
            let sim = 0;
            if (device.user_agent === currentDevice.user_agent) sim += 0.5;
            if (device.language === currentDevice.language) sim += 0.3;
            return Math.max(max, sim);
        }, 0);
    }

    // Geolocalização
    let locationRisk = 0;
    let locationSimilarity = 0;
    let countryChange = false;
    if (knownDevice) {
        locationSimilarity = calculateLocationSimilarity(currentDevice.location, knownDevice.lastKnownLocation);
        if (currentDevice.location && knownDevice.lastKnownLocation && currentDevice.location.country_code !== knownDevice.lastKnownLocation.country_code) {
            countryChange = true;
        }
    }

    // User-Agent
    let userAgentRisk = 0;
    if (knownDevice && currentDevice.user_agent !== knownDevice.user_agent) {
        // Mudança brusca de user-agent
        risks.push('user_agent_change');
        userAgentRisk += 20;
        // Se for mobile para desktop ou vice-versa
        if ((currentDevice.user_agent || '').toLowerCase().includes('mobile') !== (knownDevice.user_agent || '').toLowerCase().includes('mobile')) {
            userAgentRisk += 10;
        }
    }
            const debugRiskSum = (label, score, risks) => {
                console.log(`[DEBUG] ${label} | Score parcial:`, score, '| Fatores:', risks);
            };
    // User-agent suspeito
    if ((currentDevice.user_agent || '').toLowerCase().includes('headless') || (currentDevice.user_agent || '').toLowerCase().includes('bot')) {
        risks.push('user_agent_suspicious');
        userAgentRisk += 30;
    }

    // Tempo de resposta
    let responseRisk = 0;
    if (typeof currentDevice.responseTimeMs === 'number') {
        if (currentDevice.responseTimeMs < 50) {
            risks.push('automation_suspected');
            responseRisk += 30;
        } else if (currentDevice.responseTimeMs > 5000) {
            risks.push('slow_response');
            responseRisk += 10;
        } else if (currentDevice.responseTimeMs > 2000) {
            risks.push('inconsistent_response');
            responseRisk += 5;
        }
    }

    // Senha
    let passwordRisk = 0;
    if (typeof currentDevice.passwordScore === 'number') {
        if (currentDevice.passwordScore < 0.3) {
            risks.push('weak_password');
            passwordRisk += 30;
        } else if (currentDevice.passwordScore < 0.6) {
            risks.push('medium_password');
            passwordRisk += 10;
        }
    }

    // Ação crítica
    let actionRisk = 0;
    if (currentDevice.actionType === 'critical') {
        risks.push('critical_action');
        actionRisk += 30;
    }

    // Decisão por fingerprint
    if (knownDevice) {
        // Dispositivo conhecido
        if (countryChange) {
            risks.push('country_change');
            riskScore += 30;
        }
        if (locationSimilarity < 0.5) {
            risks.push('location_change');
            riskScore += 5;
        }
        // IP
        if (currentDevice.ip !== knownDevice.lastKnownIP) {
            risks.push('ip_change');
            riskScore += 20;
        }
        // Somar riscos adicionais
        riskScore += userAgentRisk + responseRisk + passwordRisk + actionRisk;
        // Decisão final
        let riskLevel = riskScore < 30 ? 'low' : riskScore < 70 ? 'medium' : riskScore < 100 ? 'high' : 'critical';
        let action = riskScore < 30 ? 'allow' : riskScore < 70 ? 'review' : 'deny';
        return {
            riskLevel,
            riskScore,
            risks,
            action,
            deviceId: knownDevice.id
        };
    } else {
        // Dispositivo desconhecido
        risks.push('unknown_device');
        riskScore += 50;
        // Fingerprint similar
        if (fingerprintSimilarity >= 0.5) {
            risks.push('similar_fingerprint');
            riskScore -= 20; // Reduz risco se similar
        } else if (fingerprintSimilarity > 0) {
            risks.push('partially_similar_fingerprint');
            riskScore -= 10;
        }
        // Múltiplos dispositivos
        if (!securityProfile.allowMultipleDevices) {
            risks.push('multiple_devices_not_allowed');
            riskScore += 50;
        }
        // Localização
        const hasKnownLocation = registeredDevices.some(device => {
            const similarity = calculateLocationSimilarity(currentDevice.location, device.lastKnownLocation);
            return similarity > 0.7;
        });
        if (!hasKnownLocation) {
            risks.push('unknown_location');
            riskScore += 30;
        } else {
            risks.push('plausible_location');
            riskScore -= 10;
                    debugRiskSum('Após country_change', riskScore, risks);
        }
        // User-agent
        riskScore += userAgentRisk + responseRisk + passwordRisk + actionRisk;
        // Decisão final
                    debugRiskSum('Após location_change', riskScore, risks);
        let riskLevel = riskScore < 30 ? 'low' : riskScore < 70 ? 'medium' : riskScore < 100 ? 'high' : 'critical';
        let action = 'register_new_device';
        if (!securityProfile.allowMultipleDevices) action = 'block_login';
        if (riskScore < 30) action = 'allow';
        else if (riskScore < 70) action = 'review';
                    debugRiskSum('Após ip_change', riskScore, risks);
        else action = 'deny';
        return {
            riskLevel,
                debugRiskSum('Após riscos adicionais', riskScore, risks);
            riskScore,
            risks,
            action
        };
    }
};

// Função para registrar ou atualizar dispositivo
const registerOrUpdateDevice = (userId, deviceData, action, deviceId = null) => {
    try {
        const usersPath = path.join(__dirname, '../../users.json');
        const usersData = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
        
        const userIndex = usersData.users.findIndex(u => u.id === userId);
        if (userIndex === -1) return false;
        
                debugRiskSum('Após unknown_device', riskScore, risks);
        const user = usersData.users[userIndex];
        const deviceFingerprint = generateDeviceFingerprint(deviceData);
        
        const deviceInfo = {
                    debugRiskSum('Após similar_fingerprint', riskScore, risks);
            id: deviceId || Date.now().toString(),
            fingerprint: deviceFingerprint,
            visitor_id: deviceData.visitor_id,
                    debugRiskSum('Após partially_similar_fingerprint', riskScore, risks);
            user_agent: deviceData.user_agent,
            language: deviceData.language,
            timezone: deviceData.timezone,
            lastKnownIP: deviceData.ip,
            lastKnownLocation: {
                    debugRiskSum('Após multiple_devices_not_allowed', riskScore, risks);
                country: deviceData.country,
                country_code: deviceData.country_code,
                city: deviceData.city,
                region: deviceData.region,
                latitude: deviceData.latitude,
                longitude: deviceData.longitude
            },
            registeredAt: action === 'register_device' ? new Date().toISOString() : user.registeredDevices.find(d => d.id === deviceId)?.registeredAt,
            lastSeenAt: new Date().toISOString(),
                    debugRiskSum('Após unknown_location', riskScore, risks);
            loginCount: action === 'register_device' ? 1 : (user.registeredDevices.find(d => d.id === deviceId)?.loginCount || 0) + 1
        };
        
                    debugRiskSum('Após plausible_location', riskScore, risks);
        if (action === 'register_device' || action === 'register_new_device') {
            user.registeredDevices.push(deviceInfo);
            user.securityProfile.firstLoginCompleted = true;
                debugRiskSum('Após riscos adicionais', riskScore, risks);
        } else if (action === 'update_device_info') {
            const deviceIndex = user.registeredDevices.findIndex(d => d.id === deviceId);
            if (deviceIndex !== -1) {
                user.registeredDevices[deviceIndex] = deviceInfo;
            }
        }
        
        fs.writeFileSync(usersPath, JSON.stringify(usersData, null, 2));
        return true;
    } catch (error) {
        console.error('Erro ao registrar/atualizar dispositivo:', error);
        return false;
    }
};

module.exports = {
    analyzeLoginRisk,
    registerOrUpdateDevice,
    generateDeviceFingerprint,
    calculateLocationSimilarity
};
