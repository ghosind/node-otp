/**
 * Encodes a string into a Uint8Array using UTF-8 encoding.
 *
 * @param str The string to encode.
 * @returns The encoded Uint8Array.
 */
export const encodeString = (str: string): Uint8Array => {
  return new TextEncoder().encode(str);
};
