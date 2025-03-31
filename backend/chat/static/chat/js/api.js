import { hashPassword, encryptPrivateKey, decryptPrivateKey, generateRSAKeys, encryptMessage, decryptMessage } from './cryp.js';
import { arrayBufferToBase64 } from './common.js';

export async  function registerUser(user_tag, password, nickname = null) {
    if (nickname === null) {
        nickname = user_tag
    }
    // const PASSWORD = "my_secure_password";
    // const USER_TAG = "test_user_js";
    // const NICKNAME = "JS User";
    const API_URL = "/api/register_user/";

    // Generate keys
    const { publicKeyPem, privateKeyPem } = await generateRSAKeys();
    
    // Encrypt private key
    const encryptedPrivateKey = await encryptPrivateKey(privateKeyPem, password);
    
    // Hash password
    const h1_pass = await hashPassword(password);
    
    // Prepare request data
    const data = {
        tag: user_tag,
        nickname: nickname,
        public_key: publicKeyPem,
        encrypted_private_key: arrayBufferToBase64(encryptedPrivateKey),
        h1_pass: arrayBufferToBase64(h1_pass)
    };

    // Send registration request
    const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });
    
    return response.json();
}

export async  function loginUser(user_tag, password) {
    // const USER_TAG = "test_user_js";
    // const PASSWORD = "my_secure_password";
    
    const h1_pass = await hashPassword(password);
    
    const response = await fetch("/api/user_login/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            tag: user_tag,
            h1_pass: arrayBufferToBase64(h1_pass)
        })
    });
    
    const data = await response.json();
    if (data.status !== "success") {
        return data;
    }
    const encryptedData = new Uint8Array(atob(data.encrypted_private_key).split('').map(c => c.charCodeAt(0)));
    
    const decryptedKey = await decryptPrivateKey(encryptedData, password);
    // console.log("Decrypted private key:", decryptedKey);
    data.token
    data.decryptedPrivateKey = decryptedKey
    return data;
}


export async function sendMessage(sender, receiver, content, token, pub_self, pub_other) {
    // Base64 encode the content like in Python example
    // const content_to = 
    // const encodedContent = btoa(unescape(encodeURIComponent(content)));
    const to = await encryptMessage(content, pub_other)
    const from = await encryptMessage(content, pub_self)
    
    try {
        const response = await fetch('/api/send_message/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                sender: sender,
                receiver: receiver,
                content_to: btoa(unescape(encodeURIComponent(to))),
                content_from: btoa(unescape(encodeURIComponent(from))),
                token: token
            })
        });
        
        const data = await response.json();
        console.log('Message sent:', data);
        return data;
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

export async function getMessages(tag, other, token, privateKey) {
    const response = await fetch(`/api/get_messages/${tag}/${token}/${other}/`);
    const j = await response.json();
    for (const e of j) {
        console.log(e.content_to)
        const to = decodeURIComponent(escape(atob(e.content_to)));
        const from = decodeURIComponent(escape(atob(e.content_from)));
        if (e.sender === tag) {
            e.content = await decryptMessage(from, privateKey)
        } else {
            e.content = await decryptMessage(to, privateKey)
        }
        
    }
    return j
}


export async function getRecentChats(tag, token) {
    const ret = await fetch(`/api/get_recent_chats/${tag}/${token}/`);
    return ret
}

export async function getUser(tag) {
    const ret = await fetch(`/api/fetch_user/${tag}/`);
    const j = await ret.json();
    return j
}

export async function getSelf(tag, token) {
    const ret = await fetch(`/api/fetch_self/${tag}/${token}/`);
    const j = await ret.json();
    return j
}