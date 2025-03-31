import { arrayBufferToBase64 } from './common.js';

export async function generateRSAKeys() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        },
        true,
        ["sign", "verify"]
    );

    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    
    return {
        publicKeyPem: `-----BEGIN PUBLIC KEY-----\n${arrayBufferToBase64(publicKey).match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`,
        privateKeyPem: `-----BEGIN PRIVATE KEY-----\n${arrayBufferToBase64(privateKey).match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`
    };
}

export async  function encryptPrivateKey(privateKeyPem, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    
    const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    
    const aesKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-CBC", length: 256 },
        false,
        ["encrypt"]
    );
    
    const data = new TextEncoder().encode(privateKeyPem);
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        aesKey,
        data
    );
    
    const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
    
    return combined;
}

export async function decryptPrivateKey(encryptedData, password) {
    // console.log(encryptedData, password)
    const salt = encryptedData.slice(0, 16);
    const iv = encryptedData.slice(16, 32);
    const ciphertext = encryptedData.slice(32);
    
    const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    
    const aesKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-CBC", length: 256 },
        false,
        ["decrypt"]
    );
    
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        aesKey,
        ciphertext
    );
    
    return new TextDecoder().decode(decrypted);
}

export async function hashPassword(password) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(password)
    );
    return new Uint8Array(digest);
}


export async  function encryptMessage(message, publicKeyPem) {
    // Convert PEM to ArrayBuffer
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    const pemContents = publicKeyPem
        .replace(pemHeader, '')
        .replace(pemFooter, '')
        .replace(/\s+/g, '');
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    
    // Import public key
    const publicKey = await crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["encrypt"]
    );
    
    // Encrypt message
    const encrypted = await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        new TextEncoder().encode(message)
    );
    
    return arrayBufferToBase64(encrypted);
}

export async  function decryptMessage(base64Ciphertext, privateKeyPem) {
    // Convert PEM to ArrayBuffer
    // console.log(base64Ciphertext)
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    const pemContents = privateKeyPem
        .replace(pemHeader, '')
        .replace(pemFooter, '')
        .replace(/\s+/g, '');
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    
    // Import private key
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["decrypt"]
    );
    
    // Decrypt message
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        privateKey,
        Uint8Array.from(atob(base64Ciphertext), c => c.charCodeAt(0))
    );
    
    return new TextDecoder().decode(decrypted);
}