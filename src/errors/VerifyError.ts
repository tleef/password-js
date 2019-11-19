export default class VerifyError extends Error {
  constructor(message: string) {
    super(message);

    // Set the prototype explicitly.
    Object.setPrototypeOf(this, VerifyError.prototype);
  }
}
