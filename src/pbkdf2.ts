import type from "@tleef/type-js";
import * as crypto from "crypto";
import HashError from "./errors/HashError";
import VerifyError from "./errors/VerifyError";
import { IAlgorithm } from "./types";

export interface IOptions {
  iterations: number;
  keyLength: number;
  digest: string;
}

const NAME = "pbkdf2";

const DIGESTS = ["sha1", "sha256", "sha512"];

const DEFAULTS: IOptions = {
  iterations: 100000,
  keyLength: 256,
  digest: "sha512",
};

function hash(
  password: string,
  salt: Buffer,
  options?: Partial<IOptions>,
): Promise<string> {
  options = options || {};

  const iterations = options.iterations || DEFAULTS.iterations;
  const keyLength = options.keyLength || DEFAULTS.keyLength;
  const digest = options.digest || DEFAULTS.digest;

  validateOptions(iterations, keyLength, digest, HashError);

  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keyLength, digest, (err, key) => {
      if (err) {
        reject(err);
        return;
      }

      const hashedPassword = `${NAME}$${iterations}$${keyLength}$${digest}$${salt.toString(
        "hex",
      )}$${key.toString("hex")}`;

      resolve(hashedPassword);
    });
  });
}

async function verify(password: string, checkHash: string) {
  const parts = checkHash.split("$");

  if (parts.length !== 6) {
    throw new VerifyError("hash not formatted correctly");
  }

  const name = parts[0];
  const iterations = parseInt(parts[1], 10);
  const keyLength = parseInt(parts[2], 10);
  const digest = parts[3];
  const salt = Buffer.from(parts[4], "hex");

  if (name !== NAME) {
    throw new VerifyError("hash uses wrong algorithm");
  }

  validateOptions(iterations, keyLength, digest, VerifyError);

  const hashedPassword = await hash(password, salt, {
    iterations,
    keyLength,
    digest,
  });

  return hashedPassword === checkHash;
}

function validateOptions<E extends Error>(
  iterations: number,
  keyLength: number,
  digest: string,
  err: new (message: string) => E,
) {
  if (!type.isInteger(iterations) || iterations <= 0) {
    throw new err("iterations must be a positive integer");
  }

  if (!type.isInteger(keyLength) || keyLength <= 0) {
    throw new err("keyLength must be a positive integer");
  }

  if (!DIGESTS.includes(digest)) {
    throw new err(`digest must be one of ${DIGESTS.join(", ")}`);
  }
}

const pbkdf2: IAlgorithm = {
  name: NAME,
  hash,
  verify,
};

export default pbkdf2;
