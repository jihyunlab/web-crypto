const crypto = globalThis.crypto;

export const KeyHelper = {
  async pbkdf2(
    cipher: string,
    length: number,
    password: string,
    salt: string,
    iterations: number
  ) {
    const textEncoder = new TextEncoder();

    const baseKey = await crypto.subtle.importKey(
      'raw',
      textEncoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: 'SHA-512',
        salt: textEncoder.encode(salt),
        iterations: iterations,
      },
      baseKey,
      {
        name: cipher,
        length: length,
      },
      true,
      ['encrypt', 'decrypt']
    );

    return key;
  },
};
