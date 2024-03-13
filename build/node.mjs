import { objectType, addMutationFields, addQueryFields, builder } from "fuse";
import "dotenv/config";
import { Keypair, Transaction } from "@solana/web3.js";
import bs58 from "bs58";
import { MongoClient } from "mongodb";
import { setup, assign, fromPromise, createActor, toPromise } from "xstate";
import crypto from "crypto";
import http from "http";
import { createYoga } from "graphql-yoga";
import { blockFieldSuggestionsPlugin } from "@escape.tech/graphql-armor-block-field-suggestions";
import { useDeferStream } from "@graphql-yoga/plugin-defer-stream";
import { useDisableIntrospection } from "@graphql-yoga/plugin-disable-introspection";
import { createStellateLoggerPlugin } from "stellate/graphql-yoga";

async function connectDB(config) {
  if (!config.mongoURI) {
    throw new Error("Mongo URI is undefined");
  }
  if (!config.dbName) {
    throw new Error("Database name is undefined");
  }
  const client = new MongoClient(config.mongoURI);
  await client.connect();
  const db = client.db(config.dbName);
  return { client, db };
}
function createDBConnection(config) {
  if (!config) {
    throw new Error("Connection config is undefined");
  }
  const { mongoURI, dbName } = config;
  if (!mongoURI) {
    throw new Error("Mongo URI is undefined");
  }
  if (!dbName) {
    throw new Error("Database name is undefined");
  }
  return connectDB({ mongoURI, dbName });
}

const iv = process.env.IV_KEY;
function generateKey(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
function decryptData(data, key) {
  if (iv) {
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(key, "hex"),
      Buffer.from(iv, "hex")
    );
    let decryptedData = decipher.update(data, "hex", "utf-8");
    decryptedData += decipher.final("utf8");
    const credentials = JSON.parse(decryptedData);
    return credentials;
  }
  return null;
}
async function generateAccount(key) {
  if (iv) {
    let cipher = crypto.createCipheriv(
      "aes-256-cbc",
      Buffer.from(key, "hex"),
      Buffer.from(iv, "hex")
    );
    const keyPair = await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ]);
    const pubBuff = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const pubKey = bs58.encode(new Uint8Array(pubBuff));
    const pubArray = new Uint8Array(pubBuff);
    const pkBuff = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
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

const { db } = await createDBConnection({
  mongoURI: process.env.DB_URI || "",
  dbName: process.env.DB_NAME || "",
});
const registerAccountMachine = setup({
  types: {
    context: {},
    events: {},
    output: {},
  },
  actions: {
    saveIds: assign({
      id: ({ event }) => event.id,
      appId: ({ event }) => event.appId,
      pin: ({ event }) => event.pin,
    }),
  },
  actors: {
    fetchLogins: fromPromise(async ({ input }) => {
      if (!input.id) {
        throw new Error("ID not set");
      }
      const appKey = generateKey([input.id, input.appId].join("%"));
      const isRegisteredInApp = await db
        .collection("auth")
        .findOne({ id: appKey });
      const mainKey = generateKey(input.id);
      const isRegistered = await db.collection("auth").findOne({ id: mainKey });
      return {
        isRegisteredInApp: isRegisteredInApp !== null,
        isRegistered: isRegistered !== null,
      };
    }),
    registerAccount: fromPromise(async ({ input }) => {
      if (!input.id) {
        throw new Error("ID not set");
      }
      const storeKey = generateKey(input.id);
      const cipherKey = generateKey([input.id, input.pin].join("$"));
      if (storeKey && cipherKey) {
        const credentials = await generateAccount(cipherKey);
        const doc = await db.collection("auth").insertOne({
          id: storeKey,
          credentials,
        });
        return doc.insertedId;
      }
      return new Error("Registration failed");
    }),
    registerAppAccount: fromPromise(async ({ input }) => {
      if (!input.id) {
        throw new Error("ID not set");
      }
      const storeKey = generateKey([input.id, input.appId].join("%"));
      const cipherKey = generateKey(
        [input.id, input.pin, input.appId].join("$")
      );
      if (storeKey && cipherKey) {
        const credentials = await generateAccount(cipherKey);
        const doc = await db.collection("auth").insertOne({
          id: storeKey,
          credentials,
        });
        return doc.insertedId;
      }
      return new Error("Registration failed");
    }),
  },
  guards: {
    isNewAccount: function ({ context }) {
      return (
        context.isRegistered === false && context.isRegisteredInApp === false
      );
    },
    isNewAppAccount: function ({ context }) {
      return (
        context.isRegistered === true && context.isRegisteredInApp === false
      );
    },
    hasAppId: function ({ context }) {
      return (context.appId && context.appId.length > 0) || false;
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
          appId: context.appId,
        }),
        onDone: {
          target: "validating",
          actions: assign({
            isRegistered: ({ event }) => event.output.isRegistered || false,
            isRegisteredInApp: ({ event }) =>
              event.output.isRegisteredInApp || false,
          }),
        },
        onError: {
          target: "error",
          actions: assign({
            error: "Failed fetching login details",
          }),
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
            error: "Account already registered",
          }),
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
          pin: context.pin,
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
            error: "Failed registering account",
          }),
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
            error: "Failed registering app account",
          }),
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
    error: context.error,
  }),
});

const RegistrationResponseType = objectType({
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
      pin: t.arg.int({ required: true }),
      appId: t.arg.string({ required: false }),
    },
    resolve: async (_, args) => {
      const registerAccount = createActor(registerAccountMachine);
      registerAccount.start();
      registerAccount.send({
        type: "register",
        id: args.id,
        appId: args.appId,
        pin: args.pin,
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
      const { db } = await createDBConnection({
        mongoURI: process.env.DB_URI || "",
        dbName: process.env.DB_NAME || "",
      });
      const storeKey = generateKey(args.id);
      const entry = await db.collection("auth").findOne({ id: storeKey });
      if (entry && storeKey) {
        const cipherKey = generateKey([args.id, args.pin].join("$"));
        try {
          const data = decryptData(entry.credentials, cipherKey);
          if (data) {
            const signer = Keypair.fromSecretKey(bs58.decode(data?.privKey));
            const transaction = Transaction.from(
              Buffer.from(args.tx, "base64")
            );
            transaction.partialSign(signer);
            const serializedTransaction = transaction.serialize({
              requireAllSignatures: false,
              verifySignatures: false,
            });
            console.log(serializedTransaction);
            const transactionBase64 = serializedTransaction.toString("base64");
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
const LoginType = objectType({
  name: "Login",
  fields: (t) => ({
    pubKey: t.exposeString("pubKey"),
  }),
});
addQueryFields((t) => ({
  loginAccount: t.field({
    type: LoginType,
    args: {
      id: t.arg.string({ required: true }),
      pin: t.arg.int({ required: true }),
      appId: t.arg.string({ required: false }),
    },
    resolve: async (_, args) => {
      const { db } = await createDBConnection({
        mongoURI: process.env.DB_URI || "",
        dbName: process.env.DB_NAME || "",
      });
      const entry = args.appId ? [args.id, args.appId].join("%") : args.id;
      const storeKey = generateKey(entry);
      const data = await db.collection("auth").findOne({ id: storeKey });
      if (data && storeKey) {
        const cipher = args.appId
          ? [args.id, args.pin, args.appId].join("$")
          : [args.id, args.pin].join("$");
        const cipherKey = generateKey(cipher);
        try {
          return decryptData(data.credentials, cipherKey);
        } catch (e) {
          return null;
        }
      }
    },
  }),
}));

const getContext = (ctx) => {
  return {
    ua: ctx.request.headers.get("user-agent"),
  };
};

const __vite_glob_1_0 = /*#__PURE__*/ Object.freeze(
  /*#__PURE__*/ Object.defineProperty(
    {
      __proto__: null,
      getContext,
    },
    Symbol.toStringTag,
    { value: "Module" }
  )
);

var getYogaPlugins = (stellate) => {
  return [
    useDeferStream(),
    process.env.NODE_ENV === "production" && useDisableIntrospection(),
    process.env.NODE_ENV === "production" && blockFieldSuggestionsPlugin(),
    Boolean(process.env.NODE_ENV === "production" && stellate) &&
      createStellateLoggerPlugin({
        serviceName: stellate.serviceName,
        token: stellate.loggingToken,
        fetch,
      }),
  ].filter(Boolean);
};
var wrappedContext = (context) => {
  return async (ct) => {
    const baseContext = {
      request: ct.request,
      headers: ct.request.headers,
      params: ct.params,
    };
    if (typeof context === "function") {
      const userCtx = context(baseContext);
      if (userCtx.then) {
        const result = await userCtx;
        return {
          ...baseContext,
          ...result,
        };
      }
      return {
        ...baseContext,
        ...userCtx,
      };
    } else if (typeof context === "object") {
      return {
        ...baseContext,
        ...context,
      };
    }
    return baseContext;
  };
};

// src/adapters/node.ts
async function main() {
  let ctx;
  const context = /* #__PURE__ */ Object.assign({
    "/_context.ts": __vite_glob_1_0,
  });
  if (context["/_context.ts"]) {
    const mod = context["/_context.ts"];
    if (mod.getContext) {
      ctx = mod.getContext;
    }
  }
  const completedSchema = builder.toSchema({});
  const yoga = createYoga({
    graphiql: false,
    maskedErrors: true,
    schema: completedSchema,
    // We allow batching by default
    batching: true,
    context: wrappedContext(ctx),
    plugins: getYogaPlugins({
      serviceName: "simpl3",
      token:
        "stl8log_ad7a6715b7e138f40cfbdf980c2e13c5b34c94a2bb8ddb7524cd1e7b5a16bac6",
    }),
  });
  const server = http.createServer(yoga);
  server.listen(process.env.PORT || 4e3);
}
main();

export { main };
