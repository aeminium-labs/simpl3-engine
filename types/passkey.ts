import { addMutationFields } from "fuse";

import "dotenv/config";

import { createDBConnection } from "@/utils/db";
import { generateKey } from "@/utils/crypto";
import type { AuthenticationResponseJSON, AuthenticatorTransportFuture, CredentialDeviceType, RegistrationResponseJSON } from '@simplewebauthn/types';
import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';

type UserModel = {
    id: string;
    username: string;
    authenticators: Authenticator[];
    currentChallenge?: string;
};

type Authenticator = {
    credentialID: string;
    credentialPublicKey: string;
    counter: number;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    transports?: AuthenticatorTransportFuture[];
};

const rpName = 'Simpl3 Auth';
const rpID = 'localhost';
const origin = `https://${rpID}`;

addMutationFields((t) => ({
    startRegistration: t.field({
        type: "String",
        args: {
            id: t.arg.string({ required: true }),
            appId: t.arg.string({ required: false }),
        },
        resolve: async (_, args) => {
            const { db } = await createDBConnection({ mongoURI: process.env.DB_URI || "", dbName: process.env.DB_NAME || "" })

            const userId = generateKey(args.id);
            let user: UserModel | null = await db.collection<UserModel>("passkeys").findOne({ id: userId });

            if (!user) {
                user = {
                    id: userId,
                    username: args.id,
                    authenticators: [],
                }
            }

            if (!user.authenticators) {
                user.authenticators = [];
            }

            const options = await generateRegistrationOptions({
                rpName,
                rpID,
                userID: user.id,
                userName: user.username,
                // Don't prompt users for additional information about the authenticator
                // (Recommended for smoother UX)
                attestationType: 'none',
                // Prevent users from re-registering existing authenticators
                excludeCredentials: user.authenticators.map(authenticator => ({
                    id: Buffer.from(authenticator.credentialID, "base64url"),
                    type: 'public-key',
                    // Optional
                    transports: authenticator.transports,
                })),
                // See "Guiding use of authenticators via authenticatorSelection" below
                authenticatorSelection: {
                    // Defaults
                    residentKey: 'preferred',
                    userVerification: 'preferred',
                    // Optional
                    authenticatorAttachment: 'cross-platform',
                },
            });

            await db.collection("passkeys").updateOne({ id: userId }, {
                $set: {
                    id: userId,
                    username: user.username,
                    currentChallenge: options.challenge,
                }
            }, { upsert: true })

            return JSON.stringify(options);

        },
    }),
    finishRegistration: t.field({
        type: "Boolean",
        args: {
            id: t.arg.string({ required: true }),
            response: t.arg.string({ required: true }),
            appId: t.arg.string({ required: false }),
        },
        resolve: async (_, args) => {
            const { db } = await createDBConnection({ mongoURI: process.env.DB_URI || "", dbName: process.env.DB_NAME || "" })

            const userId = generateKey(args.id);
            let user: UserModel | null = await db.collection<UserModel>("passkeys").findOne({ id: userId });

            if (!user || !user.currentChallenge) {
                throw new Error();
            }

            let verification;
            const data = JSON.parse(args.response) as RegistrationResponseJSON;
            try {
                verification = await verifyRegistrationResponse({
                    response: data,
                    expectedChallenge: user?.currentChallenge,
                    expectedOrigin: origin,
                    expectedRPID: rpID,
                });
            } catch (e) {
                console.log(e)
                throw new Error();
            }

            const { verified, registrationInfo } = verification;

            if (registrationInfo) {
                const {
                    credentialPublicKey,
                    credentialID,
                    counter,
                    credentialDeviceType,
                    credentialBackedUp,
                } = registrationInfo;

                const newAuthenticator: Authenticator = {
                    credentialID: Buffer.from(credentialID).toString("base64url"),
                    credentialPublicKey: Buffer.from(credentialPublicKey).toString("base64"),
                    counter,
                    credentialDeviceType,
                    credentialBackedUp,
                    transports: data.response.transports,
                };

                await db.collection<UserModel>("passkeys").updateOne({ id: userId }, {
                    $push: {
                        "authenticators": newAuthenticator
                    }
                })
            }

            return verified;

        },
    }),
    startAuthentication: t.field({
        type: "String",
        args: {
            id: t.arg.string({ required: true }),
            appId: t.arg.string({ required: false }),
        },
        resolve: async (_, args) => {
            console.log(args)
            const { db } = await createDBConnection({ mongoURI: process.env.DB_URI || "", dbName: process.env.DB_NAME || "" })

            const userId = generateKey(args.id);
            let user: UserModel | null = await db.collection<UserModel>("passkeys").findOne({ id: userId });

            if (!user) {
                throw new Error("No user")
            }

            const options = await generateAuthenticationOptions({
                rpID,
                // Require users to use a previously-registered authenticator
                allowCredentials: user.authenticators.map(authenticator => ({
                    id: Buffer.from(authenticator.credentialID, "base64url"),
                    type: 'public-key',
                    transports: authenticator.transports,
                })),
                userVerification: 'preferred',
                timeout: 1000,
            });

            await db.collection("passkeys").updateOne({ id: userId }, {
                $set: {
                    currentChallenge: options.challenge,
                }
            })

            return JSON.stringify(options);
        },
    }),
    finishAuthentication: t.field({
        type: "Boolean",
        args: {
            id: t.arg.string({ required: true }),
            response: t.arg.string({ required: true }),
            appId: t.arg.string({ required: false }),
        },
        resolve: async (_, args) => {
            const { db } = await createDBConnection({ mongoURI: process.env.DB_URI || "", dbName: process.env.DB_NAME || "" })

            const userId = generateKey(args.id);
            let user: UserModel | null = await db.collection<UserModel>("passkeys").findOne({ id: userId });

            if (!user || !user.currentChallenge) {
                throw new Error();
            }

            const data = JSON.parse(args.response) as AuthenticationResponseJSON;

            const authenticator = user.authenticators.find(authenticator => authenticator.credentialID === data.id)

            if (!authenticator) {
                throw new Error(`Could not find authenticator ${data.id} for user ${user.id}`);
            }

            let verification;
            try {
                verification = await verifyAuthenticationResponse({
                    response: data,
                    expectedChallenge: user.currentChallenge,
                    expectedOrigin: origin,
                    expectedRPID: rpID,
                    authenticator: {
                        credentialID: Buffer.from(authenticator.credentialID, "base64url"),
                        counter: authenticator.counter,
                        credentialPublicKey: Buffer.from(authenticator.credentialPublicKey, "base64")
                    },
                });
            } catch (e) {
                console.log(e)
                throw new Error();
            }

            const { verified, authenticationInfo } = verification;


            if (authenticationInfo) {
                const { newCounter } = authenticationInfo;
                await db.collection<UserModel>("passkeys").updateOne({ id: userId }, {
                    $set: {
                        "authenticators.$[elem].counter": newCounter
                    },
                }, { arrayFilters: [{ "elem.credentialID": authenticator.credentialID }] })
            }

            return verified;

        },
    }),
}));



