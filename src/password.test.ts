/* eslint-env mocha */

import * as chai from "chai";
import * as sinon from "sinon";
import * as sinonChai from "sinon-chai";
import * as chaiAsPromised from "chai-as-promised";

import * as crypto from "crypto";

import pwd from "./password";
import pbkdf2 from "./pbkdf2";

const expect = chai.expect;

chai.use(sinonChai);
chai.use(chaiAsPromised);

describe("password.ts", () => {
  describe("#hash()", () => {
    it("should successfully hash a password", async () => {
      const hash = await pwd.hash("SuperSecretPassword", undefined, undefined, {
        iterations: 100,
      });

      expect(hash).to.be.a("string");
    });

    it("should throw if password is not a string", async () => {
      // @ts-ignore
      await expect(pwd.hash(123)).to.be.rejectedWith(
        "password must be a non-empty String",
      );
    });

    it("should throw if password is an empty string", async () => {
      // @ts-ignore
      await expect(pwd.hash("")).to.be.rejectedWith(
        "password must be a non-empty String",
      );
    });

    describe("pbkdf2", () => {
      beforeEach(() => {
        sinon.stub(crypto, "pbkdf2");
      });
      afterEach(() => {
        // @ts-ignore
        crypto.pbkdf2.restore();
      });

      it("should throw if crypto.pbkdf2() returns an error", () => {
        // @ts-ignore
        crypto.pbkdf2.callsArgWith(5, new Error("some error"));
        // @ts-ignore
        expect(pwd.hash("SuperSecretPassword")).to.be.rejectedWith(
          "error hashing password with pbkdf2",
        );
      });
    });

    describe("randomBytes", () => {
      beforeEach(() => {
        sinon.stub(crypto, "randomBytes");
      });
      afterEach(() => {
        // @ts-ignore
        crypto.randomBytes.restore();
      });

      it("should throw if crypto.randomBytes() returns an error", () => {
        // @ts-ignore
        crypto.randomBytes.callsArgWith(1, new Error("some error"));
        // @ts-ignore
        expect(pwd.hash("SuperSecretPassword")).to.be.rejectedWith(
          "error generating salt",
        );
      });
    });
  });

  describe("#verify()", () => {
    it("should successfully verify a password", async () => {
      const res = await pwd.verify(
        "SuperSecretPassword",
        await pwd.hash("SuperSecretPassword", undefined, undefined, {
          iterations: 100,
        }),
      );

      expect(res).to.equal(true);
    });

    it("should not verify incorrectly password", async () => {
      const res = await pwd.verify(
        "SuperSecretPassword",
        await pwd.hash("superSecretPassword", undefined, undefined, {
          iterations: 100,
        }),
      );

      expect(res).to.equal(false);
    });

    it("should throw if password is not a string", async () => {
      // @ts-ignore
      await expect(pwd.verify(123, "test")).to.be.rejectedWith(
        "password must be a non-empty String",
      );
    });

    it("should throw if password is an empty string", async () => {
      // @ts-ignore
      await expect(pwd.verify("", "test")).to.be.rejectedWith(
        "password must be a non-empty String",
      );
    });

    it("should throw if hash is not a string", async () => {
      // @ts-ignore
      await expect(pwd.verify("test", 123)).to.be.rejectedWith(
        "hash must be a non-empty String",
      );
    });

    it("should throw if hash is an empty string", async () => {
      // @ts-ignore
      await expect(pwd.verify("test", "")).to.be.rejectedWith(
        "hash must be a non-empty String",
      );
    });

    it("should throw if hash is wrong length", async () => {
      // @ts-ignore
      await expect(
        pwd.verify("test", `${pbkdf2.name}$two$three`),
      ).to.be.rejectedWith("hash not formatted correctly");
    });

    it("should throw if hash is not supported", async () => {
      // @ts-ignore
      await expect(pwd.verify("test", "bad$two$three")).to.be.rejectedWith(
        "algorithm is not supported",
      );
    });
  });
});
