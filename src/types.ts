export type HashFunction = (
  password: string,
  salt: Buffer,
  options?: any,
) => Promise<string>;
export type VerifyFunction = (
  password: string,
  checkHash: string,
) => Promise<boolean>;

export interface IAlgorithm {
  name: string;
  hash: HashFunction;
  verify: VerifyFunction;
}
