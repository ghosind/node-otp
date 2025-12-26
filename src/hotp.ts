import { OTP } from './otp';

/**
 * HMAC-based One-Time Password (HOTP) generator and verifier.
 */
export class HOTP extends OTP {
  /**
   * Generates an HOTP code based on the provided secret and counter.
   *
   * @param secret The shared secret key used for generating the HOTP code.
   * @param counter The counter value used for generating the HOTP code.
   * @returns The generated HOTP code as a string.
   */
  async generate(secret: string, counter?: number): Promise<string> {
    return this.generateCode(secret, counter || 0);
  }

  /**
   * Verifies the provided HOTP code against the generated code for the given secret and counter.
   *
   * @param secret The shared secret key used for generating the HOTP code.
   * @param token The HOTP code to verify.
   * @param counter The counter value used for generating the HOTP code.
   * @returns A boolean indicating whether the HOTP code is valid.
   */
  async verify(secret: string, token: string, counter?: number): Promise<boolean> {
    return this.verifyCode(secret, token, counter || 0);
  }

  /**
   * Generates the OTP URI for the given parameters.
   *
   * @param secret The shared secret key used for generating the HOTP code.
   * @param accountName The account name associated with the OTP.
   * @param counter The counter value used for generating the HOTP code.
   * @returns The generated OTP URI as a string.
   */
  getURI(secret: string, accountName: string, counter?: number): string {
    const params: Record<string, string> = {
      counter: (counter || 0).toString(),
    };

    return this.buildURI('hotp', secret, accountName, params);
  }
}
