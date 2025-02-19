# RSA Azure Key-Vault Encryption

Enterprise-level encryption

```ts
//
//
// FRONTEND
//
//

// accessToken is from the users signed in session
// store the public key in localStorage to prevent unnecessary requests
const getPublicKey = async (accessToken: string) => {
    const res = await fetch(
        "https://<YOUR_KEYVAULT_NAME>.vault.azure.net/keys/MyRSAKey?api-version=7.3",
        {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        }
    );

    const data = await res.json();

    return data.key.n; // Public Key modulus (part of JWK format)
}

// this is called in the useCache.ts file
// data -> data to encrypt
// publicKey -> from function above
const encryptData(data: string, publicKey: string): Promise<string> {
    const _publicKey = forge.pki.publicKeyFromPem(publicKey);
    const encrypted = _publicKey.encrypt(data, "RSA-OAEP");

    return forge.util.encode64(encrypted);
}

//
//
// BACKEND
//
//

// pretty sure azure has a javascript library for this instead of sending http requests
//
// accessToken is sent in the http request headers
async function decryptData(encryptedData: string, accessToken: string): Promise<string> {
    const url = "https://<YOUR_KEYVAULT_NAME>.vault.azure.net/decrypt?api-version=7.3";
    
    const response = await fetch(url, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            alg: "RSA-OAEP",
            value: encryptedData,
        }),
    });

    const data = await response.json();

    return Buffer.from(data.value, "base64").toString("utf-8");
}

// Azure Key Vault supports automatic key rotation. Just enable it and then encrypt the following instead of ONLY the data:
const dataToEncrypt = JSON.stringify({
    data: sensitiveData,
    expiresAt: Date.now() + 3600 * 1000, // Expires in 1 hour
});
```
