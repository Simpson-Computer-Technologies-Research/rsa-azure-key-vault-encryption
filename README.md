# RSA Azure Key-Vault Encryption

Enterprise-level encryption

```ts
//
//
// FRONTEND
//
//

import forge from "node-forge";
import axios from "axios";

/**
 * Get public key from Azure Key Vault
 * 
 * @param azureAccessToken Azure access token
 * 
 * @returns Public key
 * 
 * @example
 * const publicKey = await getPublicKey({ azureAccessToken });
 */
export const getPublicKey = async ({ azureAccessToken }: { azureAccessToken: string }) => {
    const url = "https://<YOUR_KEYVAULT_NAME>.vault.azure.net/keys/MyRSAKey?api-version=7.3";

    const res = await axios.get(url, {
        headers: {
            Authorization: `Bearer ${azureAccessToken}`,
        }
    });

    const json = await res.json();

    return json.key.n;
}

/**
 * Encrypt data with a public key (RSA)
 * 
 * @param data Data to encrypt
 * @param publicKey Public key to encrypt with
 * @param expiresAt Expiration date in milliseconds
 * 
 * @returns Encrypted data
 * 
 * @example
 * const publicKey = await getPublicKey({ azureAccessToken });
 * const encrypted = await encrypt({ data: "Hello, World!", publicKey, expiresAt: Date.now() + 3600 * 1000 }); // Expires in 1 hour
 */
export const encrypt = async ({ data, publicKey, expiresAt }: Readonly<{ data: string | undefined; publicKey: string; expiresAt?: number }>) => {
    const _toEncrypt = expiresAt !== undefined ? JSON.stringify({ data, expiresAt }) : data;

    const _publicKey = forge.pki.publicKeyFromPem(publicKey);

    const encrypted = _publicKey.encrypt(_toEncrypt, "RSA-OAEP");

    return forge.util.encode64(encrypted);
}

//
//
// BACKEND
//
//

/**
 * Decrypt data with a private key (RSA)
 * 
 * @param data Data to decrypt
 * @param privateKey Private key to decrypt with
 * 
 * @returns Decrypted data
 * 
 * @example
 * const decrypted = await decrypt({ data: encrypted, azureAccessToken });
 */
export const decrypt = async ({ data, azureAccessToken }: Readonly<{ data: string | undefined; azureAccessToken: string; }>) => {
    const url = "https://<YOUR_KEYVAULT_NAME>.vault.azure.net/decrypt?api-version=7.3";

    const res = await axios.post(url, {
        alg: "RSA-OAEP",
        value: data,
    }, {
        headers: {
            Authorization: `Bearer ${azureAccessToken}`,
            "Content-Type": "application/json",
        }
    });

    const json = await res.json();

    return forge.util.decode64(json.value);
}
```
