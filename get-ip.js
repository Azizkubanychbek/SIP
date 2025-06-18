const os = require('os');

function getLocalIP() {
    const interfaces = os.networkInterfaces();
    
    for (const name of Object.keys(interfaces)) {
        for (const interface of interfaces[name]) {
            // Пропускаем IPv6 и loopback
            if (interface.family === 'IPv4' && !interface.internal) {
                return interface.address;
            }
        }
    }
    return 'localhost';
}

const localIP = getLocalIP();
console.log('🌐 Ваш IP адрес в сети:', localIP);
console.log('📱 Для доступа с телефона используйте:');
console.log(`   http://${localIP}:3000`);
console.log('');
console.log('💡 Если не открывается с телефона:');
console.log('   1. Убедитесь, что телефон и компьютер в одной Wi-Fi сети');
console.log('   2. Временно отключите Windows Firewall');
console.log('   3. Или разрешите входящие подключения для Node.js'); 