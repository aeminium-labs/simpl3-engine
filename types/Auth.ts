import { addMutationFields, addQueryFields } from "fuse";
import { objectType } from "fuse";

import "dotenv/config";

import { Keypair, Transaction } from "@solana/web3.js";
import bs58 from "bs58";
import { createDBConnection } from "@/utils/db";
import { createActor, toPromise } from "xstate";
import { RegisterAccount, registerAccountMachine } from "@/machines/registerAccount.machine";
import { checkCircleAccount, decryptData, generateKey, getCircleAccount } from "@/utils/crypto";
import { Wallet } from "@circle-fin/developer-controlled-wallets/dist/types/clients/developer-controlled-wallets";

const RegistrationResponseType = objectType<RegisterAccount>({
    name: "RegistrationResponse",
    fields: (t) => ({
        success: t.exposeBoolean("success"),
        error: t.exposeString("error"),
    }),
});

addMutationFields((t) => ({
    registerAccount: t.field({
        type: RegistrationResponseType,
        args: {
            id: t.arg.string({ required: true }),
            pin: t.arg.string({ required: true }),
            appId: t.arg.string({ required: false }),
        },
        resolve: async (_, args) => {
            const registerAccount = createActor(registerAccountMachine);

            registerAccount.start();

            registerAccount.send({
                type: "register",
                id: args.id,
                appId: args.appId,
                pin: args.pin
            });

            return await toPromise(registerAccount);
        },
    }),
    sign: t.field({
        type: "String",
        args: {
            id: t.arg.string({ required: true }),
            pin: t.arg.int({ required: true }),
            tx: t.arg.string({ required: true }),
        },
        resolve: async (_, args) => {
            const { db } = await createDBConnection({ mongoURI: process.env.DB_URI || "", dbName: process.env.DB_NAME || "" })

            const storeKey = generateKey(args.id);
            const entry = await db.collection("auth").findOne({ id: storeKey });

            if (entry && storeKey) {
                const cipherKey = generateKey([args.id, args.pin].join("$"));

                try {
                    const data = decryptData(entry.credentials, cipherKey);

                    if (data) {
                        const signer = Keypair.fromSecretKey(
                            bs58.decode(data?.privKey)
                        );
                        const transaction = Transaction.from(
                            Buffer.from(args.tx, "base64")
                        );

                        transaction.partialSign(signer);

                        const serializedTransaction = transaction.serialize({
                            requireAllSignatures: false,
                            verifySignatures: false,
                        });


                        const transactionBase64 =
                            serializedTransaction.toString("base64");

                        return transactionBase64;
                    }
                } catch (e) {
                    console.log(e);
                    return null;
                }
            }

            return null;
        },
    }),
}));

const LoginType = objectType<Wallet>({
    name: "Login",
    fields: (t) => ({
        pubKey: t.exposeString("address"),
    }),
});

const CheckAccountType = objectType<{ isRegisteredInApp: boolean; isRegistered: boolean; }>({
    name: "CheckAccount",
    fields: (t) => ({
        isRegisteredInApp: t.exposeBoolean("isRegisteredInApp"),
        isRegistered: t.exposeBoolean("isRegistered")
    }),
});

addQueryFields((t) => ({
    checkAccount: t.field({
        type: CheckAccountType,
        args: {
            id: t.arg.string({ required: true }),
            appId: t.arg.string({ required: false }),
        },
        resolve: async (_, args) => {
            // Check if ID is registered in App
            const refId = generateKey(args.id);
            const isRegisteredInApp = await checkCircleAccount({ refId, appId: args.appId });

            // Check if ID is registered in Simpl3
            const isRegistered = await checkCircleAccount({ refId });

            return {
                isRegisteredInApp,
                isRegistered,
            }
        },
    }),
    loginAccount: t.field({
        type: LoginType,
        args: {
            id: t.arg.string({ required: true }),
            pin: t.arg.string({ required: true }),
            appId: t.arg.string({ required: false }),
        },
        resolve: async (_, args) => {
            const refId = generateKey(args.id);
            const security = generateKey([args.id, args.pin].join("$"));

            const wallet = await getCircleAccount({ refId, appId: args.appId, security });

            try {
                return wallet;
            } catch (e) {
                return null;
            }
        },
    }),
}));
