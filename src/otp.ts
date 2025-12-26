import { Base32Encoding } from '@antmind/encoding';
import { Algorithm, hmac } from './crypto';

const DefaultAlgorithm: Algorithm = 'SHA1';
const DefaultDigits = 6;

export interface OTPOptions {
  /**
   * The algorithm used for the OTP generation, typically 'SHA1', 'SHA256', or 'SHA512'.
   * Default is 'SHA1'.
   */
  algorithm?: Algorithm;

  /**
   * The number of digits in the generated OTP, typically 6 or 8. Default is 6.
   */
  digits?: number;

  /**
   * The issuer name to be included in the OTP URI.
   */
  issuer?: string;
}

export abstract class OTP {
  /**
   * The algorithm used for the OTP generation, typically 'SHA1', 'SHA256', or 'SHA512'.
   * Default is 'SHA1'.
   */
  algorithm?: Algorithm;

  /**
   * The number of digits in the generated OTP, typically 6 or 8. Default is 6.
   */
  digits?: number;

  /**
   * The issuer name to be included in the OTP URI.
   */
  issuer?: string | undefined;

  private base32?: Base32Encoding;

  constructor(options?: OTPOptions) {
    this.algorithm = options?.algorithm || DefaultAlgorithm;
    this.digits = options?.digits || DefaultDigits;
    this.issuer = options?.issuer;
  }

  abstract generate(secret: string, counterOrTime?: number): Promise<string>;

  abstract verify(secret: string, token: string, counterOrTime?: number): Promise<boolean>;

  /**
   * Verifies the provided OTP code against the generated code for the given secret and counter or
   * time.
   *
   * @param secret The shared secret key used for generating the OTP code.
   * @param token The OTP code to verify.
   * @param counter The counter or time value used for generating the OTP code.
   * @returns A boolean indicating whether the OTP code is valid.
   */
  protected async verifyCode(secret: string, token: string, counter: number): Promise<boolean> {
    const generatedCode = await this.generateCode(secret, counter);

    return generatedCode === token;
  }

  /**
   * Generates an OTP code based on the provided secret and counter or time.
   *
   * @param secret The shared secret key used for generating the OTP code.
   * @param counter The counter or time value used for generating the OTP code.
   * @returns The generated OTP code as a string.
   */
  protected async generateCode(secret: string, counter: number): Promise<string> {
    const message = new Uint8Array(8);
    const view = new DataView(message.buffer);
    view.setUint32(4, counter, false);
    const secretBytes = new TextEncoder().encode(secret);

    const hash = await hmac(this.algorithm, secretBytes, message);
    const offset = (hash[hash.length - 1] || 0) & 0x0f;
    const code = (((hash[offset] || 0) & 0x7F) << 24)
      | (((hash[offset+1] || 0) & 0xFF) << 16)
      | (((hash[offset+2] || 0) & 0xFF) << 8)
      | ((hash[offset+3] || 0) & 0xFF);
    const mod = 10 ** (this.digits || DefaultDigits);
    const otp = (code % mod).toString().padStart(this.digits || DefaultDigits, '0');

    return otp;
  }

  /**
   * Builds the OTP URI for the given OTP type, secret, account name, and other parameters.
   *
   * @param type The type of OTP, either 'totp' or 'hotp'.
   * @param secret The shared secret key used for generating the OTP code.
   * @param accountName The account name associated with the OTP.
   * @param otherParams Additional parameters to include in the OTP URI.
   * @returns The generated OTP URI as a string.
   */
  protected buildURI(type: 'totp' | 'hotp', secret: string, accountName: string, otherParams: {
    [key: string]: string | number;
  }): string {
    const params = new URLSearchParams();

    const base32 = this.getBase32();
    const secretBase32 = base32.encode(secret);
    params.append('secret', secretBase32);

    if (this.issuer) {
      params.append('issuer', this.issuer);
    }
    if (this.algorithm && this.algorithm !== DefaultAlgorithm) {
      params.append('algorithm', this.algorithm);
    }
    if (this.digits && this.digits !== DefaultDigits) {
      params.append('digits', (this.digits).toString());
    }

    for (const [key, value] of Object.entries(otherParams)) {
      params.append(key, value.toString());
    }

    const path = this.issuer
      ? `${encodeURIComponent(this.issuer)}:${encodeURIComponent(accountName)}`
      : encodeURIComponent(accountName);

    return `otpauth://${type}/${path}?${params.toString()}`;
  }

  /**
   * Gets the Base32 encoding instance.
   *
   * @returns The base32 encoding instance.
   */
  private getBase32(): Base32Encoding {
    if (!this.base32) {
      this.base32 = new Base32Encoding({ padChar: '' });
    }

    return this.base32;
  }
}
