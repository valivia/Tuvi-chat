// use this to encrypt/decrypt message-keys
export function generateKeypair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey({ name: "RSA-OAEP" }, false, ["encrypt", "decrypt"]) as Promise<CryptoKeyPair>;
}

// use this for messages
export function generateKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey({ name: "AES-GCM" }, true, ["encrypt", "decrypt"]) as Promise<CryptoKey>;
}

export function importKey(pemKey: string): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "spki",
        convertPemToBinary(pemKey),
        { name: "AES-GCM" },
        true,
        ["encrypt"]
    )
}

export async function exportKey(key: CryptoKey): Promise<string>{
    return convertBinaryToPem(await window.crypto.subtle.exportKey('spki', key), "key")
}

function base64StringToArrayBuffer(b64str: string) {
    const byteStr = atob(b64str)
    const bytes = new Uint8Array(byteStr.length)
    for (let i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i)
    }
    return bytes.buffer
}

function arrayBufferToBase64String(arrayBuffer: ArrayBuffer) {
    const byteArray = new Uint8Array(arrayBuffer)
    let byteString = ''
    for (let i = 0; i < byteArray.byteLength; i++) {
        byteString += String.fromCharCode(byteArray[i])
    }
    return btoa(byteString)
}

function convertBinaryToPem(binaryData: ArrayBuffer, label: string) {
    const base64Cert = arrayBufferToBase64String(binaryData)
    let pemCert = "-----BEGIN " + label + "-----\r\n"
    let nextIndex = 0
    // let lineLength
    while (nextIndex < base64Cert.length) {
        if (nextIndex + 64 <= base64Cert.length) {
            pemCert += base64Cert.substr(nextIndex, 64) + "\r\n"
        } else {
            pemCert += base64Cert.substr(nextIndex) + "\r\n"
        }
        nextIndex += 64
    }
    pemCert += "-----END " + label + "-----\r\n"
    return pemCert
}
function convertPemToBinary(pem: string) {
    const lines = pem.split('\n')
    let encoded = ''
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim().length > 0 &&
            lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
            encoded += lines[i].trim()
        }
    }
    return base64StringToArrayBuffer(encoded)
}
