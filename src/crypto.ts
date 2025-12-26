import { createHmac } from 'crypto';

/**
 * The supported HMAC algorithms.
 */
export type Algorithm = 'SHA1' | 'SHA256' | 'SHA512';

/**
 * Generates an HMAC digest for the given message using the specified algorithm and key.
 *
 * @param algorithm The HMAC algorithm to use. Default is 'SHA1'.
 * @param key The secret key used for HMAC generation.
 * @param message The message to be hashed.
 * @returns The generated HMAC digest as a Uint8Array.
 */
export const hmac = async (
  algorithm: Algorithm = 'SHA1',
  key: Uint8Array,
  message: Uint8Array,
) => {
  const hmac = createHmac(algorithm, key);
  hmac.update(message);

  return new Uint8Array(hmac.digest());
}
