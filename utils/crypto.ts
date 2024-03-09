import crypto from "crypto";
import bs58 from "bs58";

const iv = process.env.IV_KEY;

export function generateKey(value: string) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

export type Credentials = {
    pubKey: string;
    privKey: string;
};

export function decryptData(data: string, key: string) {
    if (iv) {
        const decipher = crypto.createDecipheriv(
            "aes-256-cbc",
            Buffer.from(key, "hex"),
            Buffer.from(iv, "hex")
        );

        let decryptedData = decipher.update(data, "hex", "utf-8");

        decryptedData += decipher.final("utf8");

        const credentials: Credentials = JSON.parse(decryptedData);

        return credentials;
    }

    return null;
}

export async function generateAccount(key: string) {
    if (iv) {
        let cipher = crypto.createCipheriv(
            "aes-256-cbc",
            Buffer.from(key, "hex"),
            Buffer.from(iv, "hex")
        );

        const keyPair = (await crypto.subtle.generateKey("Ed25519", true, [
            "sign",
            "verify",
        ])) as CryptoKeyPair;

        const pubBuff = await crypto.subtle.exportKey("raw", keyPair.publicKey);
        const pubKey = bs58.encode(new Uint8Array(pubBuff));
        const pubArray = new Uint8Array(pubBuff);
        const pkBuff = await crypto.subtle.exportKey(
            "pkcs8",
            keyPair.privateKey
        );
        const pkArray = new Uint8Array(pkBuff).slice(16, 48);
        const pkFull = new Uint8Array([...pkArray, ...pubArray]);

        const privKey = bs58.encode(pkFull);

        const dataWithWallet = JSON.stringify({
            pubKey,
            privKey,
        });

        let encryptedData = cipher.update(dataWithWallet, "utf-8", "hex");

        encryptedData += cipher.final("hex");

        return encryptedData;
    }

    return "";
}
