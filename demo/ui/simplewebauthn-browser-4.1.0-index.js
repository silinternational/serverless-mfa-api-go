/* [@simplewebauthn/browser]  Version: 4.1.0 - Wednesday, September 1st, 2021, 9:11:50 AM */
function utf8StringToBuffer(value) {
    return new TextEncoder().encode(value);
}

function bufferToBase64URLString(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
    }
    const base64String = btoa(str);
    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLStringToBuffer(base64URLString) {
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLength, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
}

function browserSupportsWebauthn() {
    return ((window === null || window === void 0 ? void 0 : window.PublicKeyCredential) !== undefined && typeof window.PublicKeyCredential === 'function');
}

function toPublicKeyCredentialDescriptor(descriptor) {
    const { id } = descriptor;
    return {
        ...descriptor,
        id: base64URLStringToBuffer(id),
    };
}

async function startRegistration(creationOptionsJSON) {
    if (!browserSupportsWebauthn()) {
        throw new Error('WebAuthn is not supported in this browser');
    }
    const publicKey = {
        ...creationOptionsJSON,
        challenge: base64URLStringToBuffer(creationOptionsJSON.challenge),
        user: {
            ...creationOptionsJSON.user,
            id: utf8StringToBuffer(creationOptionsJSON.user.id),
        },
        excludeCredentials: creationOptionsJSON.excludeCredentials.map(toPublicKeyCredentialDescriptor),
    };
    const credential = (await navigator.credentials.create({ publicKey }));
    if (!credential) {
        throw new Error('Registration was not completed');
    }
    const { id, rawId, response, type } = credential;
    const credentialJSON = {
        id,
        rawId: bufferToBase64URLString(rawId),
        response: {
            attestationObject: bufferToBase64URLString(response.attestationObject),
            clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
        },
        type,
        clientExtensionResults: credential.getClientExtensionResults(),
    };
    if (typeof response.getTransports === 'function') {
        credentialJSON.transports = response.getTransports();
    }
    return credentialJSON;
}

function bufferToUTF8String(value) {
    return new TextDecoder('utf-8').decode(value);
}

async function startAuthentication(requestOptionsJSON) {
    var _a, _b;
    if (!browserSupportsWebauthn()) {
        throw new Error('WebAuthn is not supported in this browser');
    }
    let allowCredentials;
    if (((_a = requestOptionsJSON.allowCredentials) === null || _a === void 0 ? void 0 : _a.length) !== 0) {
        allowCredentials = (_b = requestOptionsJSON.allowCredentials) === null || _b === void 0 ? void 0 : _b.map(toPublicKeyCredentialDescriptor);
    }
    const publicKey = {
        ...requestOptionsJSON,
        challenge: base64URLStringToBuffer(requestOptionsJSON.challenge),
        allowCredentials,
    };
    const credential = (await navigator.credentials.get({ publicKey }));
    if (!credential) {
        throw new Error('Authentication was not completed');
    }
    const { id, rawId, response, type } = credential;
    let userHandle = undefined;
    if (response.userHandle) {
        userHandle = bufferToUTF8String(response.userHandle);
    }
    return {
        id,
        rawId: bufferToBase64URLString(rawId),
        response: {
            authenticatorData: bufferToBase64URLString(response.authenticatorData),
            clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
            signature: bufferToBase64URLString(response.signature),
            userHandle,
        },
        type,
        clientExtensionResults: credential.getClientExtensionResults(),
    };
}

async function platformAuthenticatorIsAvailable() {
    if (!browserSupportsWebauthn()) {
        return false;
    }
    return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}

export { browserSupportsWebauthn, platformAuthenticatorIsAvailable, startAuthentication, startRegistration };
