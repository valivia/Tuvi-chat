class E2ECrypt {
    // use this to encrypt/decrypt message-keys
    async generateKeypair(): Promise<CryptoKeyPair> {
        return await crypto.subtle.generateKey({ name: "RSA-OAEP" }, false, ["encrypt", "decrypt"]) as CryptoKeyPair;
    }

    // use this for messages
    async generateKey(): Promise<CryptoKey> {
        return await crypto.subtle.generateKey({ name: "AES-GCM" }, true, ["encrypt", "decrypt"]) as CryptoKey;
    }

    arrayBufferToBase64String(arrayBuffer: number[]) {
        const byteArray = new Uint8Array(arrayBuffer)
        let byteString = ''
        for (let i = 0; i < byteArray.byteLength; i++) {
            byteString += String.fromCharCode(byteArray[i])
        }
        return btoa(byteString)
    }

    base64StringToArrayBuffer(b64str: string) {
        const byteStr = atob(b64str)
        const bytes = new Uint8Array(byteStr.length)
        for (let i = 0; i < byteStr.length; i++) {
            bytes[i] = byteStr.charCodeAt(i)
        }
        return bytes.buffer
    }

    textToArrayBuffer(str: string) {
        const buf = unescape(encodeURIComponent(str)) // 2 bytes for each char
        const bufView = new Uint8Array(buf.length)
        for (let i = 0; i < buf.length; i++) {
            bufView[i] = buf.charCodeAt(i)
        }
        return bufView
    }

    arrayBufferToText(arrayBuffer: number[]) {
        const byteArray = new Uint8Array(arrayBuffer)
        let str = ''
        for (let i = 0; i < byteArray.byteLength; i++) {
            str += String.fromCharCode(byteArray[i])
        }
        return str
    }

    arrayBufferToBase64(arr: number[]) {
        return btoa(String.fromCharCode.apply(null, arr))
    }

    convertBinaryToPem(binaryData: number[], label: string) {
        const base64Cert = this.arrayBufferToBase64String(binaryData)
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

    convertPemToBinary(pem: string) {
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
        return this.base64StringToArrayBuffer(encoded)
    }

    importPublicEncryptKey(pemKey: string) {
        // return new Promise(function (resolve) {
        //     const importer = crypto.subtle.importKey("spki", convertPemToBinary(pemKey), encryptAlgorithm, true, ["encrypt"])
        //     importer.then(function (key) {
        //         resolve(key)
        //     }).catch((e) => console.log(e.message))
        // })
        return crypto.subtle.importKey(
            "spki",
            this.convertPemToBinary(pemKey),
            this.encryptAlgorithm,
            true,
            ["encrypt"]
        ) as Promise<CryptoKey>
    }

    importPublicKey(pemKey) {
        return new Promise(function (resolve) {
            const importer = crypto.subtle.importKey("spki", convertPemToBinary(pemKey), signAlgorithm, true, ["verify"])
            importer.then(function (key) {
                resolve(key)
            })
        })
    }

    importPrivateKey(pemKey) {
        return new Promise(function (resolve) {
            const importer = crypto.subtle.importKey("pkcs8", convertPemToBinary(pemKey), signAlgorithm, true, ["sign"])
            importer.then(function (key) {
                resolve(key)
            })
        })
    }

    importPrivateDecryptKey(pemKey) {
        return new Promise(function (resolve) {
            const importer = crypto.subtle.importKey("pkcs8", convertPemToBinary(pemKey), encryptAlgorithm, true, ["decrypt"])
            importer.then(function (key) {
                resolve(key)
            })
        })
    }

    exportPublicKey(keys) {
        return new Promise(function (resolve) {
            window.crypto.subtle.exportKey('spki', keys.publicKey).
                then(function (spki) {
                    resolve(convertBinaryToPem(spki, "RSA PUBLIC KEY"))
                })
        })
    }

    exportPrivateKey(keys) {
        return new Promise(function (resolve) {
            const expK = window.crypto.subtle.exportKey('pkcs8', keys.privateKey)
            expK.then(function (pkcs8) {
                resolve(convertBinaryToPem(pkcs8, "RSA PRIVATE KEY"))
            })
        })
    }

    exportPemKeys(keys) {
        return new Promise(function (resolve) {
            exportPublicKey(keys).then(function (pubKey) {
                exportPrivateKey(keys).then(function (privKey) {
                    resolve({ publicKey: pubKey, privateKey: privKey })
                })
            })
        })
    }

    signData(key, data) {
        return window.crypto.subtle.sign(signAlgorithm, key, data)
    }

    testVerifySig(pub, sig, data) {
        return crypto.subtle.verify(signAlgorithm, pub, sig, data)
    }

    encryptData(key, data) {
        return crypto.subtle.encrypt(
            {
                name: "RSA-OAEP",
                //iv: vector
            },
            key,
            textToArrayBuffer(data)
        )
    }

    decryptData(key, data) {
        return crypto.subtle.decrypt(
            {
                name: "RSA-OAEP",
                //iv: vector
            },
            key,
            data
        )
    }

    signAlgorithm = {
        name: "RSASSA-PKCS1-v1_5",
        hash: {
            name: "SHA-256"
        },
        modulusLength: 2048,
        extractable: false,
        publicExponent: new Uint8Array([1, 0, 1])
    }

    encryptAlgorithm = {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        extractable: false,
        hash: {
            name: "SHA-256"
        }
    }

    deriveKey(saltBuf, passphrase) {
        const keyLenBits = 128;
        const kdfname = "PBKDF2";
        const aesname = "AES-CBC"; // AES-CTR is also popular
        // 100 - probably safe even on a browser running from a raspberry pi using pure js ployfill
        // 10000 - no noticeable speed decrease on my MBP
        // 100000 - you can notice
        // 1000000 - annoyingly long
        const iterations = 100; // something a browser on a raspberry pi or old phone could do
        const hashname = "SHA-256";
        const extractable = true;

        console.log('');
        console.log('passphrase', passphrase);
        console.log('salt (hex)', Unibabel.bufferToHex(saltBuf));
        console.log('iterations', iterations);
        console.log('keyLen (bytes)', keyLenBits / 8);
        console.log('digest', hashname);

        // First, create a PBKDF2 "key" containing the password
        return crypto.subtle.importKey(
            "raw",
            Unibabel.utf8ToBuffer(passphrase),
            { "name": kdfname },
            false,
            ["deriveKey"]).
            // Derive a key from the password
            then(function (passphraseKey) {
                return crypto.subtle.deriveKey(
                    {
                        "name": kdfname
                        , "salt": saltBuf
                        , "iterations": iterations
                        , "hash": hashname
                    }
                    , passphraseKey
                    // required to be 128 (or 256) bits
                    , { "name": aesname, "length": keyLenBits } // Key we want
                    , extractable                               // Extractble
                    , ["encrypt", "decrypt"]                  // For new key
                );
            }).
            // Export it so we can display it
            then(function (aesKey) {
                return aesKey;
                return crypto.subtle.exportKey("raw", aesKey).then(function (arrbuf) {
                    return new Uint8Array(arrbuf);
                });
            }).
            catch(function (err) {
                window.alert("Key derivation failed: " + err.message);
            });
    }

    deriveKeyFromBuffer(saltBuf, KeyBuffer) {
        const keyLenBits = 128;
        const kdfname = "PBKDF2";
        const aesname = "AES-CBC"; // AES-CTR is also popular
        // 100 - probably safe even on a browser running from a raspberry pi using pure js ployfill
        // 10000 - no noticeable speed decrease on my MBP
        // 100000 - you can notice
        // 1000000 - annoyingly long
        const iterations = 100; // something a browser on a raspberry pi or old phone could do
        const hashname = "SHA-256";
        const extractable = true;

        // First, create a PBKDF2 "key" containing the KeyBuffer
        return crypto.subtle.importKey(
            "raw",
            KeyBuffer,
            { "name": kdfname },
            false,
            ["deriveKey"]).
            // Derive a key from the KeyBuffer
            then(function (passphraseKey) {
                return crypto.subtle.deriveKey(
                    {
                        "name": kdfname
                        , "salt": saltBuf
                        , "iterations": iterations
                        , "hash": hashname
                    }
                    , passphraseKey
                    // required to be 128 (or 256) bits
                    , { "name": aesname, "length": keyLenBits } // Key we want
                    , extractable                               // Extractble
                    , ["encrypt", "decrypt"]                  // For new key
                );
            }).
            // Export it so we can display it
            then(function (aesKey) {
                return aesKey;
                return crypto.subtle.exportKey("raw", aesKey).then(function (arrbuf) {
                    return new Uint8Array(arrbuf);
                });
            }).
            catch(function (err) {
                window.alert("Key derivation failed: " + err.message);
            });
    }

    async encryptMessage(publicKey, msg, IV) {
        if (IV == null) {
            IV = myIV;
        }
        const enc = new TextEncoder();
        const encoded = enc.encode(msg);
        const arr = await window.crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: IV
            },
            publicKey,
            encoded
        );
        console.log(new Uint8Array(arr))
        return JSON.stringify(Array.from(new Uint8Array(arr)));
    }

    async decryptMessage(publicKey, msg, IV) {
        //let parts = separateIvFromData(buf);//parts.iv, parts.data
        if (IV == null) {
            IV = myIV;
        }
        const dec = new TextDecoder("utf-8");
        const buf = new Uint8Array(JSON.parse(msg));
        console.log(buf);
        const arr = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: IV }, publicKey, buf)
        console.log(buf);
        return dec.decode(arr);
    }

    async decryptAESData(publicKey, buf, IV) {
        //let parts = separateIvFromData(buf);//parts.iv, parts.data
        if (IV == null) {
            IV = myIV;
        }
        const dec = new TextDecoder("utf-8");
        console.log(buf);
        const arr = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: IV }, publicKey, buf)
        console.log(buf);
        return dec.decode(arr);
    }

    async generateKeys(passwd, func) {
        if (
            localStorage.getItem('signKeyS').indexOf("-----BEGIN RSA PRIVATE KEY-----") !== -1 &&
            localStorage.getItem('encryptKeyS').indexOf("-----BEGIN RSA PRIVATE KEY-----") !== -1
        )
            return func(localStorage.getItem("encryptKeyS"), localStorage.getItem("signKeyS"));
        const ekeys = await generateKey(encryptAlgorithm, scopeEncrypt);
        encryptKey = ekeys.privateKey;
        const publicEKey = await exportPublicKey(ekeys)
        localStorage.setItem('encryptKeyP', publicEKey);
        const privateEKey = await exportPrivateKey(ekeys)
        localStorage.setItem('encryptKeyS', privateEKey);
        const skeys = await generateKey(encryptAlgorithm, scopeEncrypt)
        signKey = skeys.privateKey;
        const publicSKey = await exportPublicKey(skeys);
        localStorage.setItem('signKeyP', publicSKey);
        const privateSKey = await exportPrivateKey(skeys);
        localStorage.setItem('signKeyS', privateSKey);

        func(privateEKey, privateSKey);
    }

    separateIvFromData(buf) {
        const iv = new Uint8Array(ivLen);
        const data = new Uint8Array(buf.length - ivLen);
        Array.prototype.forEach.call(buf, function (byte, i) {
            if (i < ivLen) {
                iv[i] = byte;
            } else {
                data[i - ivLen] = byte;
            }
        });
        return { iv: iv, data: data };
    }



    scopeSign = ["sign", "verify"]
    scopeEncrypt = ["encrypt", "decrypt"]

    encryptKey = false;
    signKey = false;

    start() {
        myIV = localStorage.getItem('myIV')
        if (myIV == null) {
            myIV = window.crypto.getRandomValues(new Uint8Array(16));
            localStorage.setItem('myIV', JSON.stringify(myIV));
        } else {
            myIV = new Uint8Array(Object.values(JSON.parse(myIV)));
        }
    }

    start2() {
        if (localStorage.getItem('signKeyS') != null && localStorage.getItem('encryptKeyS') != null &&
            localStorage.getItem('signKeyS').indexOf("-----BEGIN RSA PRIVATE KEY-----") !== -1 &&
            localStorage.getItem('encryptKeyS').indexOf("-----BEGIN RSA PRIVATE KEY-----") !== -1) {
            importPrivateKey(localStorage.getItem('signKeyS')).then(function (Skey) {
                importPrivateDecryptKey(localStorage.getItem('encryptKeyS')).then(function (Ekey) {
                    signKey = Skey;
                    encryptKey = Ekey;
                    console.log("successfully imported Private Keys")
                })
            });
        }
    }

    getLocalstorage() {
        if (localStorage.getItem('encryptKeyP') == null || localStorage.getItem('encryptKeyS') == null)
            generateKey(encryptAlgorithm, scopeEncrypt).then(function (keys) {
                encryptKey = keys.privateKey;
                exportPublicKey(keys).then((key) => {
                    localStorage.setItem('encryptKeyP', key);
                    console.log("PushEncryptKey" + key)
                    //socket.emit("PushEncryptKey",key);
                })
                exportPrivateKey(keys).then((key) => {
                    localStorage.setItem('encryptKeyS', key);
                })
            }).catch((e) => console.log(e.message))
        else {
            const key = localStorage.getItem('encryptKeyP');
            importPublicEncryptKey(key).then((key) => {
                encryptKey = key;
            })
            console.log("PushEncryptKey" + key)
            //socket.emit("PushEncryptKey",key);
        }

        if (localStorage.getItem('signKeyP') == null || localStorage.getItem('signKeyS') == null)
            generateKey(encryptAlgorithm, scopeEncrypt).then(function (keys) {
                signKey = keys.privateKey;
                exportPublicKey(keys).then((key) => {
                    localStorage.setItem('signKeyP', key);
                    console.log("PushEncryptKey" + key)
                    //socket.emit("PushEncryptKey",key);
                })
                exportPrivateKey(keys).then((key) => {
                    localStorage.setItem('signKeyS', key);
                })
            }).catch((e) => console.log(e.message))
        else {
            const key = localStorage.getItem('signKeyP');
            importPublicKey(key).then((key) => {
                signKey = key;
            })
            console.log("PushSignKey" + key)
            //socket.emit("PushSignKey",key);
        }

        const publicKeys = {};
    }
}

class E2E {
    constructor(address) {
        this.address = address;

        this.callbacks = {};
        this.sends = {};
        this.connect();
    }
    connect(options) {// {keyPair, }
        this.ws = new WebSocket(this.address);
        const that = this;
        this.ws.onopen = function () {
            if (that.resolve)
                that.resolve();
            that.callbacks["login"] = [(msg) => {
                const uid = parseInt(msg["uid"], 32);

                const FromBase64 = function (str) {
                    return new Uint8Array(atob(str).split('').map(function (c) { return c.charCodeAt(0); }));
                }
                console.log("from", FromBase64(msg["rS"]));
                const privateKey = await importPrivateDecryptKey(localStorage.getItem("encryptKeyS"));
                const randomMessage = await decryptData(privateKey, FromBase64(msg["rS"]));
                console.log(uid);
                that.uid = uid;
                users[uid] = { "uid": uid, "name": localStorage.getItem('name') || "me" };
                console.log(randomMessage);
                console.log(arrayBufferToText(randomMessage));
                that.send("randomMsg", { "randomMsg": arrayBufferToText(randomMessage) });
                console.log(msg);

                if (that.callbacks["ConnectionOpened"])
                    for (const callback of that.callbacks["ConnectionOpened"]) {
                        callback();
                    }
            }];

            if (!options.keyPair) {
                if (localStorage.getItem("encryptKeyS").indexOf("-----BEGIN RSA PRIVATE KEY-----") !== -1 &&
                    localStorage.getItem("signKeyS").indexOf("-----BEGIN RSA PRIVATE KEY-----") !== -1 &&
                    localStorage.getItem("uid") != null) {
                    // document.getElementById('register').value = "Login";
                    that.privateEKey = await importPrivateDecryptKey(localStorage.getItem("encryptKeyS"));
                    that.privateSKey = await importPrivateDecryptKey(localStorage.getItem("signKeyS"));
                    console.log("uid", parseInt(localStorage.getItem("uid"), 10).toString(32));
                    that.send("login", { "uid": parseInt(localStorage.getItem("uid"), 10).toString(32) });
                }


                let hash;
                if (localStorage.getItem("hash") == null) {
                    hash = b64_sha256(window.prompt("password", "a") + msg.salt);
                    localStorage.setItem("hash", hash);
                } else {
                    hash = localStorage.getItem("hash");
                }
                const auth = b64_sha256(hash + msg.challenge)

                return that.send('Authenticate', { auth: auth }).then(function (msg) {
                    if (msg.status !== "ok")
                        return that.connect();
                    that.send("SetHeartbeat", { "enable": false });
                    that.send("GetSceneList").then(function (msg) {
                        that.currentScene = msg["current-scene"];
                        that.sceneList = msg["scenes"]
                    });
                    if (that.callbacks["ConnectionOpened"])
                        for (const callback of that.callbacks["ConnectionOpened"]) {
                            callback();
                        }
                });
            }
        }

        this.ws.onclose = function (e) {
            if (e.reason !== "") {
                console.log('Socket is closed. Reconnect will be attempted in 1 second.', e.reason);
                setTimeout(function () {
                    that.connect();
                }, 1000);
            }
        };

        this.ws.onerror = function (err) {
            console.error('Socket encountered error: ', err.message, 'Closing socket');
            ws.close();
        };

        this.ws.onmessage = function (message) {
            const msg = JSON.parse(message.data);
            console.log(msg)
            if (that.callbacks[msg["update-type"]])
                for (const callback of that.callbacks[msg["update-type"]]) {
                    callback(msg);
                }
            else if (that.sends[msg["message-id"]]) {
                that.sends[msg["message-id"]](msg);
            }
        };

        return new Promise(function (resolve, reject) {
            try {
                that.resolve = resolve;
            } catch (e) {
                reject(e);
            }
        })
    }
    on(type, callback) {
        if (this.callbacks[type] == null)
            this.callbacks[type] = [];
        this.callbacks[type].push(callback);
    }
    send(type, options) {
        const that = this;
        if (this.ws.readyState === WebSocket.OPEN)
            return new Promise(function (resolve, reject) {
                try {
                    const mid = Math.random().toString(36).substring(7);
                    console.log("sending", Object.assign({ "request-type": type, "message-id": mid }, options));
                    that.ws.send(JSON.stringify(Object.assign({ "request-type": type, "message-id": mid }, options)));
                    that.sends[mid] = resolve;
                } catch (e) {
                    reject(e);
                }
            })
        else
            return new Promise(function (resolve, reject) {
                that.connect().then(function () {
                    const mid = Math.random().toString(36).substring(7);
                    console.log("sending", Object.assign({ "request-type": type, "message-id": mid }, options));
                    that.ws.send(JSON.stringify(Object.assign({ "request-type": type, "message-id": mid }, options)));
                    that.sends[mid] = resolve;
                });
            })
    }
}

export { E2ECrypt, E2E }