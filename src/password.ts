import * as crypto from "crypto";

import type from "@tleef/type-js";

const saltLen = 64;

const params = {
  pbkdf2: {
    digest: "sha512",
    iterations: 100000,
    keyLen: 256,
  },
};

const hash = async (password: string, salt?: string) => {
  if (!password || !type.isString(password)) {
    throw new Error("password must be a non-empty String");
  }

  let saltBuf;

  if (type.isString(salt)) {
    saltBuf = Buffer.from(salt as string, "hex");
  }

  if (!saltBuf) {
    try {
      saltBuf = await randomBytes(saltLen);
    } catch (e) {
      throw new Error("error generating salt");
    }
  }

  let key;

  try {
    key = await pbkdf2(
      password,
      saltBuf,
      params.pbkdf2.iterations,
      params.pbkdf2.keyLen,
      params.pbkdf2.digest,
    );
  } catch (e) {
    throw new Error("error hashing password with pbkdf2");
  }

  return `pbkdf2$${params.pbkdf2.iterations}$${saltBuf.toString(
    "hex",
  )}$${key.toString("hex")}`;
};

const verify = async (password: string, checkHash: string) => {
  if (!password || !type.isString(password)) {
    throw new Error("password must be a non-empty String");
  }

  if (!checkHash || !type.isString(checkHash)) {
    throw new Error("hash must be a non-empty String");
  }

  const key = checkHash.split("$");

  if (key.length !== 4 || !key[0] || !key[1] || !key[2] || !key[3]) {
    throw new Error("hash not formatted correctly");
  }

  if (key[0] !== "pbkdf2") {
    throw new Error("hash uses wrong algorithm");
  }

  if (key[1] !== params.pbkdf2.iterations.toString()) {
    throw new Error("hash uses wrong number of iterations");
  }

  const hashedPassword = await hash(password, key[2]);

  return hashedPassword === checkHash;
};

function pbkdf2(
  password: string,
  salt: Buffer,
  iterations: number,
  keyLen: number,
  digest: string,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      password,
      salt,
      iterations,
      keyLen,
      digest,
      (err, derivedKey) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(derivedKey);
      },
    );
  });
}

function randomBytes(size: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(size, (err, buf) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(buf);
    });
  });
}

export default {
  hash,
  verify,
};
