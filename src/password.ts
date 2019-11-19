import type from "@tleef/type-js";
import * as crypto from "crypto";
import HashError from "./errors/HashError";
import VerifyError from "./errors/VerifyError";
import pbkdf2 from "./pbkdf2";
import { HashFunction, VerifyFunction } from "./types";

const saltLen = 64;

export const algorithms = {
  pbkdf2: pbkdf2.name,
};

const hashFunctions: { [key: string]: HashFunction } = {
  [algorithms.pbkdf2]: pbkdf2.hash,
};

const verifyFunctions: { [key: string]: VerifyFunction } = {
  [algorithms.pbkdf2]: pbkdf2.verify,
};

const hash = async (
  password: string,
  salt?: string,
  algorithm = algorithms.pbkdf2,
  options?: any,
) => {
  if (!password || !type.isString(password)) {
    throw new HashError("password must be a non-empty String");
  }

  if (!Object.values(algorithms).includes(algorithm)) {
    throw new HashError("algorithm is not supported");
  }

  let saltBuf;

  if (type.isString(salt)) {
    saltBuf = Buffer.from(salt as string, "hex");
  }

  if (!saltBuf) {
    try {
      saltBuf = await randomBytes(saltLen);
    } catch (e) {
      throw new HashError("error generating salt");
    }
  }

  const hashFunction = hashFunctions[algorithm];

  try {
    return await hashFunction(password, saltBuf, options);
  } catch (e) {
    if (e instanceof HashError) {
      throw e;
    }
    throw new HashError(`error hashing password with ${algorithm}`);
  }
};

const verify = async (password: string, checkHash: string) => {
  if (!password || !type.isString(password)) {
    throw new VerifyError("password must be a non-empty String");
  }

  if (!checkHash || !type.isString(checkHash)) {
    throw new VerifyError("hash must be a non-empty String");
  }

  const key = checkHash.split("$");
  const algorithm = key[0];

  if (!Object.values(algorithms).includes(algorithm)) {
    throw new VerifyError("algorithm is not supported");
  }

  const verifyFunction = verifyFunctions[algorithm];

  try {
    return await verifyFunction(password, checkHash);
  } catch (e) {
    if (e instanceof VerifyError) {
      throw e;
    }
    throw new VerifyError(`error verifying password with ${algorithm}`);
  }
};

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
