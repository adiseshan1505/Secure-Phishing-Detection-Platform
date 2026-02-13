function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function stringToArrayBuffer(str) {
    return new TextEncoder().encode(str);
}

async function importAESKey(keyBase64) {
    const keyBuffer = base64ToArrayBuffer(keyBase64);
    return await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
}

async function importHMACKey(keyBase64) {
    const keyBuffer = base64ToArrayBuffer(keyBase64);
    return await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
}

async function generateHMAC(data, keyBase64) {
    const hmacKey = await importHMACKey(keyBase64);
    const dataBuffer = stringToArrayBuffer(data);
    const signature = await crypto.subtle.sign('HMAC', hmacKey, dataBuffer);

    const hashArray = Array.from(new Uint8Array(signature));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function encryptPayload(payload, aesKeyBase64) {
    const payloadWithTimestamp = {
        ...payload,
        _timestamp: Math.floor(Date.now() / 1000)
    };

    const sortedPayload = Object.keys(payloadWithTimestamp)
        .sort()
        .reduce((obj, key) => {
            obj[key] = payloadWithTimestamp[key];
            return obj;
        }, {});

    const plaintext = JSON.stringify(sortedPayload);
    const aesKey = await importAESKey(aesKeyBase64);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plaintextBuffer = stringToArrayBuffer(plaintext);
    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        plaintextBuffer
    );

    const ciphertextBase64 = arrayBufferToBase64(ciphertextBuffer);
    const nonceBase64 = arrayBufferToBase64(nonce.buffer);
    const hmacSignature = await generateHMAC(ciphertextBase64, aesKeyBase64);

    return {
        ciphertext: ciphertextBase64,
        nonce: nonceBase64,
        hmac: hmacSignature,
        algorithm: 'AES-256-GCM'
    };
}

export async function performHandshake(api) {
    const response = await api.post('/auth/crypto/handshake');
    return {
        sessionId: response.data.session_id,
        aesKey: response.data.aes_key,
        algorithm: response.data.algorithm,
        expiresIn: response.data.expires_in
    };
}

export async function secureRequest(api, endpoint, payload) {
    const { sessionId, aesKey } = await performHandshake(api);
    const encryptedPayload = await encryptPayload(payload, aesKey);

    const response = await api.post(endpoint, {
        session_id: sessionId,
        encrypted_payload: encryptedPayload
    });

    return response;
}
