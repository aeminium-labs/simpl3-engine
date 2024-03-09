import { assign, fromPromise, setup } from "xstate";
import { createDBConnection } from "@/utils/db";
import { generateAccount, generateKey } from "@/utils/crypto";

const { db } = await createDBConnection({ mongoURI: process.env.DB_URI || "", dbName: process.env.DB_NAME || "" });

export type RegisterAccount = { success: boolean; error?: string; }
export const registerAccountMachine = setup({
    types: {
        context: {} as {
            id?: string;
            appId?: string | null;
            isRegistered?: boolean;
            isRegisteredInApp?: boolean;
            error?: string;
            pin?: number;
        },
        events: {} as { type: "register"; id: string; appId?: string | null; pin: number },
        output: {} as RegisterAccount
    },
    actions: {
        saveIds: assign({
            id: ({ event }) => event.id,
            appId: ({ event }) => event.appId,
            pin: ({ event }) => event.pin,
        }),
    },
    actors: {
        fetchLogins: fromPromise(async ({ input }: { input: { id?: string, appId?: string | null } }) => {
            if (!input.id) {
                throw new Error("ID not set");
            }

            // Check if ID is registered in App
            const appKey = generateKey([input.id, input.appId].join("%"));
            const isRegisteredInApp = await db.collection("auth").findOne({ id: appKey });

            // Check if ID is registered in Simpl3
            const mainKey = generateKey(input.id);
            const isRegistered = await db.collection("auth").findOne({ id: mainKey });

            return {
                isRegisteredInApp: isRegisteredInApp !== null,
                isRegistered: isRegistered !== null,
            }
        }),
        registerAccount: fromPromise(async ({ input }: { input: { id?: string; pin?: number } }) => {
            if (!input.id) {
                throw new Error("ID not set");
            }

            const storeKey = generateKey(input.id);
            const cipherKey = generateKey([input.id, input.pin].join("$"));

            if (storeKey && cipherKey) {
                const credentials = await generateAccount(cipherKey);

                const doc = await db.collection("auth").insertOne({
                    id: storeKey,
                    credentials
                })

                return doc.insertedId;
            }

            return new Error("Registration failed")
        }),
        registerAppAccount: fromPromise(async ({ input }: { input: { id?: string; pin?: number; appId?: string | null } }) => {
            if (!input.id) {
                throw new Error("ID not set");
            }

            const storeKey = generateKey([input.id, input.appId].join("%"));
            const cipherKey = generateKey([input.id, input.pin, input.appId].join("$"));

            if (storeKey && cipherKey) {
                const credentials = await generateAccount(cipherKey);

                const doc = await db.collection("auth").insertOne({
                    id: storeKey,
                    credentials
                })

                return doc.insertedId;
            }

            return new Error("Registration failed")
        }),
    },
    guards: {
        isNewAccount: function ({ context }) {
            return context.isRegistered === false && context.isRegisteredInApp === false;
        },
        isNewAppAccount: function ({ context }) {
            return context.isRegistered === true && context.isRegisteredInApp === false;
        },
        hasAppId: function ({ context }) {
            return context.appId && context.appId.length > 0 || false
        },
    },
    schemas: {
        events: {
            register: {
                type: "object",
                properties: {
                    id: {
                        type: "string",
                    },
                    appId: {
                        type: "string",
                    },
                },
            },
        },
    },
}).createMachine({
    context: {},
    id: "registerAccount",
    initial: "idle",
    states: {
        idle: {
            on: {
                register: {
                    target: "fetching",
                    actions: {
                        type: "saveIds",
                    },
                },
            },
        },
        fetching: {
            invoke: {
                id: "fetchLogins",
                input: ({ context }) => ({
                    id: context.id,
                    appId: context.appId
                }),
                onDone: {
                    target: "validating",
                    actions: assign({
                        isRegistered: ({ event }) => event.output.isRegistered || false,
                        isRegisteredInApp: ({ event }) => event.output.isRegisteredInApp || false,
                    })
                },
                onError: {
                    target: "error",
                    actions: assign({
                        error: "Failed fetching login details"
                    })
                },
                src: "fetchLogins",
            },
        },
        validating: {
            always: [
                {
                    target: "registeringAccount",
                    guard: {
                        type: "isNewAccount",
                    },
                },
                {
                    target: "registeringAppAccount",
                    guard: {
                        type: "isNewAppAccount",
                    },
                },
                {
                    target: "error",
                    actions: assign({
                        error: "Account already registered"
                    })
                },
            ],
        },
        error: {
            type: "final",
        },
        registeringAccount: {
            invoke: {
                id: "registerAccount",
                input: ({ context }) => ({
                    id: context.id,
                    pin: context.pin
                }),
                onDone: [
                    {
                        target: "registeringAppAccount",
                        guard: {
                            type: "hasAppId",
                        },
                    },
                    {
                        target: "registered",
                    },
                ],
                onError: {
                    target: "error",
                    actions: assign({
                        error: "Failed registering account"
                    })
                },
                src: "registerAccount",
            },
        },
        registeringAppAccount: {
            invoke: {
                id: "registerAppAccount",
                input: ({ context }) => ({
                    id: context.id,
                    pin: context.pin,
                    appId: context.appId,
                }),
                onDone: {
                    target: "registered",
                },
                onError: {
                    target: "error",
                    actions: assign({
                        error: "Failed registering app account"
                    })
                },
                src: "registerAppAccount",
            },
        },
        registered: {
            type: "final",

        },
    },
    output: ({ context }) => ({
        success: !context.error || context.error.length === 0,
        error: context.error
    })
});