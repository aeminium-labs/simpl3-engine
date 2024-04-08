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
            pin?: string;
        },
        events: {} as { type: "register"; id: string; appId?: string | null; pin: string },
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
        registerAccount: fromPromise(async ({ input }: { input: { id?: string; pin?: string } }) => {
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
        registerAppAccount: fromPromise(async ({ input }: { input: { id?: string; pin?: string; appId?: string | null } }) => {
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
    /** @xstate-layout N4IgpgJg5mDOIC5QCcxQJawC5mQQQGMCB7AVwDssA6dCAGzAGJUNtcBtABgF1FQAHYrHRZ0xcnxAAPRAEYAbLKqcVKgJwBmAOwAWTgCYN8gKwAaEAE9E+zVTVaTRo1v2djAX3fmWmHPiJklFQAZmBYBAAW6ORQjBDiYDTkAG7EANaJoeERADLEGOSwXLxIIILCouKSMgjGulTynJoAHJyNshpq8uZWCPrNSvr68jrNarJassaNOp7eaL64hCQU1FmR0bG4yMTIVPx0AIZYwbsAtiFhkXkFRTyS5SJiEqU1dToNTRqt7Z3dloh5BoPiZFJxZIZmhoNLJmnMQD42P4VkFkoc6LRjptGMUHkInlVXohmgMqMDtF0tGpjCSxj1EBpOB8tJxGUYdN9FMYPF4EQskctAtQ0RiIFiYjjZCUBPjKi9QDUSUpyVT5FSaSS1PSEOMGvJ9UNjDZ9SoNPDEX5BasqCLMaIJex9NKyrLntViaSVZTqbStQCEDo1B8JtS1GH9HVwUzzfzLQFrRbcJsrZQ4gkkqkMlRE8ihbjSo85e6ELIdECqHUBg4TMYwzTtfpZJwqAp9UZNEMXPIY6w4yjqDnk-HU-FyIlopnEjmU1h2FK8RU3USS2WNBWtFX9dy681tWy7MZGZoZkHSz3FrmE7GkzEZ4xtrt9kcTuds9fL5R8zLF4SFXJV+um41jue7GEoOiHiorRaFoYGjOeArDgO77Jvw-B3qO44pOkU7vngaEzl+Lo-vK0jWBM+gVpoMH6FSOiyJo2q6rBKgdAYmgMYYCF9kKb69jeUD4ehSH3sgOx7AcxynMgFzTgRSFEYWS5-n0FFUdoLh0QxGjah0ahUPogZqLRxjgmMwxaJ4vLkMQEBwJI05IQuBKkTUAC0-y9B5yiqPI1IqMaGncUsSE0PQYDOUWy46Poe4TAZrKlpwrRuM0taWbyjn9pc2SbJFylkX0aVUAMEZDBowyBjFDa2CyjJNjF3KHvqwUfsK6J2nlBaur+hWwfIBkDDCtHGbITa7v6jKUdSbIVToVJMrMmV4aFD7IPlvU1IZ0IlWonAONMRpQrCulaGuRojGljKTDB+2tTOfEXkO-Yba5cgQmuYxtEesKdGY-ojVQEHXf1EaNHCy38W1j1Iqhwkvd1JHFhMzQfIeHTQqWtbjNqpJGT6XSjKq+j3aFOaQK9xbbZ9e0HSY-QwhNvT2C2+pAky4xAtoS2eEAA */
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