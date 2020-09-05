const fs = require('fs');
const {derToPem, pemToDer, pemToPfx} = require('..');

describe('basic', () => {
    const certKey = fs.readFileSync('./assets/key.pem');
    const pemCert = fs.readFileSync('./assets/cert.pem');
    const derCert = fs.readFileSync('./assets/cert.der');

    test('should convert from pem to der', () => {  
        const conv = pemToDer(pemCert);
        expect(conv).toBeTruthy();
    });

    test('should convert from der to pem', () => {      
        const conv = derToPem(derCert);
        expect(conv).toBeTruthy();
    });

    test('should convert from pem to pfx', () => {
        const conv = pemToPfx("123456", certKey, pemCert);
        expect(conv).toBeTruthy();
    });
});