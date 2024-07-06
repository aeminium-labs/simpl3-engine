import crypto from "crypto";
import "dotenv/config";
import { initiateDeveloperControlledWalletsClient } from "@circle-fin/developer-controlled-wallets";
import base58 from "bs58";

const iv = process.env.IV_KEY;
const secret = process.env.CIRCLE_CYPHER;
const apiKey = process.env.CIRCLE_API_KEY;
const defaultAppId = process.env.CIRCLE_DEFAULT_SET || "";

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
        const pubKey = base58.encode(new Uint8Array(pubBuff));
        const pubArray = new Uint8Array(pubBuff);
        const pkBuff = await crypto.subtle.exportKey(
            "pkcs8",
            keyPair.privateKey
        );
        const pkArray = new Uint8Array(pkBuff).slice(16, 48);
        const pkFull = new Uint8Array([...pkArray, ...pubArray]);

        const privKey = base58.encode(pkFull);

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


export async function generateCircleAccount({ key, appId, security }: { key: string; appId?: string, security: string; }) {
    if (apiKey && secret) {
        const circleDeveloperSdk = initiateDeveloperControlledWalletsClient({
            apiKey,
            entitySecret: secret,
        });

        const response = await circleDeveloperSdk.createWallets({
            accountType: "EOA",
            blockchains: ["SOL-DEVNET"],
            count: 1,
            walletSetId: appId || defaultAppId,
            metadata: [
                {
                    refId: key,
                    name: security
                },
            ],
        });

        const wallet = response.data?.wallets[0];

        return wallet?.address;
    }

    return "";
}

export async function checkCircleAccount({ refId, appId }: { refId: string; appId?: string | null; }) {
    if (apiKey && secret) {
        const circleDeveloperSdk = initiateDeveloperControlledWalletsClient({
            apiKey,
            entitySecret: secret,
        });


        try {
            const listWalletsResponse = await circleDeveloperSdk.listWallets({
                walletSetId: appId || defaultAppId,
                refId
            });

            const userWallet = listWalletsResponse.data?.wallets[0];

            if (userWallet && userWallet.address != null) {
                return true
            }

        } catch (e) {
            return false;
        }

        return false;
    }

    return false;
}

export async function getCircleAccount({ refId, appId, security }: { refId: string; appId?: string | null; security: string; }) {
    if (apiKey && secret) {
        const circleDeveloperSdk = initiateDeveloperControlledWalletsClient({
            apiKey,
            entitySecret: secret,
        });

        try {

            const listWalletsResponse = await circleDeveloperSdk.listWallets({
                walletSetId: appId || defaultAppId,
                refId
            });

            const userWallet = listWalletsResponse.data?.wallets[0];

            if (userWallet && userWallet.name === security) {
                return userWallet
            }

            return null;

        } catch (e) {
            return null;
        }
    }

    return null;
}
