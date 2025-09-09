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
    
    if (registeredDevices.length === 0) {
        // Primeiro login - baixo risco
        return {
            riskLevel: 'low',
            riskScore: 0,
            risks: ['first_login'],
            action: 'register_device'
        };
    }
    
    // Verifica se o dispositivo já está registrado
    const deviceFingerprint = generateDeviceFingerprint(currentDevice);
    const knownDevice = registeredDevices.find(device => 
        device.fingerprint === deviceFingerprint
    );
    
    if (knownDevice) {
        // Dispositivo conhecido - verifica localização
        const locationSimilarity = calculateLocationSimilarity(
            currentDevice.location,
            knownDevice.lastKnownLocation
        );
        
        if (locationSimilarity < 0.5) {
            risks.push('location_change');
            riskScore += 30;
        }
        
        // Verifica IP
        if (currentDevice.ip !== knownDevice.lastKnownIP) {
            risks.push('ip_change');
            riskScore += 20;
        }
        
        return {
            riskLevel: riskScore > 70 ? 'critical' : riskScore > 40 ? 'high' : riskScore > 20 ? 'medium' : 'low',
            riskScore,
            risks,
            action: riskScore > 70 ? 'block_login' : 'update_device_info',
            deviceId: knownDevice.id
        };
    } else {
        // Dispositivo desconhecido
        risks.push('unknown_device');
        riskScore += 50;
        
        // Verifica se permite múltiplos dispositivos
        if (!securityProfile.allowMultipleDevices) {
            risks.push('multiple_devices_not_allowed');
            riskScore += 50;
        }
        
        // Verifica localização similar aos dispositivos conhecidos
        const hasKnownLocation = registeredDevices.some(device => {
            const similarity = calculateLocationSimilarity(
                currentDevice.location,
                device.lastKnownLocation
            );
            return similarity > 0.7;
        });
        
        if (!hasKnownLocation) {
            risks.push('unknown_location');
            riskScore += 30;
        }
        
        return {
            riskLevel: riskScore > 70 ? 'critical' : riskScore > 40 ? 'high' : 'medium',
            riskScore,
            risks,
            action: riskScore > 70 ? 'block_login' : (securityProfile.allowMultipleDevices ? 'register_new_device' : 'block_login')
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
        
        const user = usersData.users[userIndex];
        const deviceFingerprint = generateDeviceFingerprint(deviceData);
        
        const deviceInfo = {
            id: deviceId || Date.now().toString(),
            fingerprint: deviceFingerprint,
            visitor_id: deviceData.visitor_id,
            user_agent: deviceData.user_agent,
            language: deviceData.language,
            timezone: deviceData.timezone,
            lastKnownIP: deviceData.ip,
            lastKnownLocation: {
                country: deviceData.country,
                country_code: deviceData.country_code,
                city: deviceData.city,
                region: deviceData.region,
                latitude: deviceData.latitude,
                longitude: deviceData.longitude
            },
            registeredAt: action === 'register_device' ? new Date().toISOString() : user.registeredDevices.find(d => d.id === deviceId)?.registeredAt,
            lastSeenAt: new Date().toISOString(),
            loginCount: action === 'register_device' ? 1 : (user.registeredDevices.find(d => d.id === deviceId)?.loginCount || 0) + 1
        };
        
        if (action === 'register_device' || action === 'register_new_device') {
            user.registeredDevices.push(deviceInfo);
            user.securityProfile.firstLoginCompleted = true;
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
