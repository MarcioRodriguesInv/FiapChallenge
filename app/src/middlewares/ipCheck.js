// Função principal para coletar todos os dados
const collectUserData = async () => {
    try {
        // Executa todas as coletas em paralelo para melhor performance
        const [fingerprintResult, ipResult] = await Promise.all([
            getFingerprintData(),
            getLocationData()
        ]);

        const userData = {
            ...fingerprintResult,
            ...ipResult,
            timestamp: new Date().toISOString(),
            user_agent: navigator.userAgent,
            language: navigator.language,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };

        console.log('User data collected:', userData);
        return userData;
    } catch (error) {
        console.error('Error collecting user data:', error);
    }
};

// Função para obter fingerprint usando OpenFP
const getFingerprintData = async () => {
    try {
        const FingerprintJS = await import('https://openfpcdn.io/fingerprintjs/v4');
        const fp = await FingerprintJS.load();
        const result = await fp.get();
        
        return {
            visitor_id: result.visitorId
        };
    } catch (error) {
        console.error('Fingerprint error:', error);
        return { visitor_id: null };
    }
};

// Função para obter dados de localização
const getLocationData = async () => {
    try {
        // Primeiro, pega o IP
        const ipResponse = await fetch('https://api.ipify.org?format=json');
        const ipData = await ipResponse.json();
        
        // Depois, pega os detalhes de localização
        const locationResponse = await fetch(`https://ipapi.co/${ipData.ip}/json/`);
        const locationData = await locationResponse.json();
        
        return {
            ip: locationData.ip,
            country: locationData.country_name,
            country_code: locationData.country_code,
            city: locationData.city,
            region: locationData.region,
            latitude: locationData.latitude,
            longitude: locationData.longitude,
            timezone_api: locationData.timezone
        };
    } catch (error) {
        console.error('Location error:', error);
        return { ip: null, country: null, city: null };
    }
};

// Inicia a coleta quando a página carregar
window.addEventListener('load', () => {
    collectUserData();
});