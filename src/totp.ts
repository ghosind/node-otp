import { OTP, OTPOptions } from './otp';

const DefaultPeriod = 30;

export interface TOTPOptions extends OTPOptions {
  /**
   * The time period in seconds for which a TOTP code is valid. Default is 30 seconds.
   */
  period?: number;
}

/**
 * Time-based One-Time Password (TOTP) generator and verifier.
 */
export class TOTP extends OTP {
  /**
   * The time period in seconds for which a TOTP code is valid. Default is 30 seconds.
   */
  period?: number;

  constructor(options?: TOTPOptions) {
    super(options);
    this.period = options?.period || DefaultPeriod;
  }

  /**
   * Generates a TOTP code for the given secret and time.
   *
   * @param secret The shared secret key used for generating the TOTP code.
   * @param time The specific time (in seconds since epoch) for which to generate the TOTP code.
   * If not provided, the current time will be used.
   * @returns The generated TOTP code as a string.
   */
  async generate(secret: string, time?: number): Promise<string> {
    if (!time) {
      time = Math.floor(Date.now() / 1000);
    }
    const counter = Math.floor(time / (this.period || DefaultPeriod));

    return this.generateCode(secret, counter);
  }

  /**
   * Verifies a TOTP code for the given secret and time.
   *
   * @param secret The shared secret key used for generating the TOTP code.
   * @param token The TOTP code to verify.
   * @param time The specific time (in seconds since epoch) for which to verify the TOTP code.
   * If not provided, the current time will be used.
   * @returns A boolean indicating whether the TOTP code is valid.
   */
  async verify(secret: string, token: string, time?: number): Promise<boolean> {
    if (!time) {
      time = Math.floor(Date.now() / 1000);
    }
    const counter = Math.floor(time / (this.period || DefaultPeriod));

    return this.verifyCode(secret, token, counter);
  }

  /**
   * Generates the OTP URI for provisioning.
   *
   * @param secret The shared secret key used for generating the TOTP code.
   * @param accountName The account name (e.g., user email) to be included in the URI.
   * @returns The generated OTP URI as a string.
   */
  getURI(secret: string, accountName: string): string {
    const params: Record<string, string | number> = {};

    if (this.period && this.period !== DefaultPeriod) {
      params['period'] = this.period;
    }

    return this.buildURI('totp', secret, accountName, params);
  }
}
