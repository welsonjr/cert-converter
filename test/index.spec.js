const fs = require('fs');
const {derToPem, pemToDer, pemToPfx} = require('..');

const certKey = fs.readFileSync('./assets/key.pem');
const pemCert = fs.readFileSync('./assets/cert.pem');
const derCert = fs.readFileSync('./assets/cert.der');

describe('Basic', () => {
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


describe('Converted files should match test sample', () => {
    test('pem to der', () => {  
        const conv = pemToDer(pemCert);
        expect(conv).toBeTruthy();
        expect(conv).toStrictEqual(derCert);
    }); 

    test('der to pem', () => {      
        const conv = derToPem(derCert);
        expect(conv).toBeTruthy();
        expect(conv).toStrictEqual(pemCert);
    });
});


