import { Hash } from '../interfaces/hash.interface';

const crypto = globalThis.crypto;

export class WebCryptoHash implements Hash {
  private readonly hash: string;

  private constructor(hash: string) {
    this.hash = hash;
  }

  public static async create(cipher: string) {
    const instance = new WebCryptoHash(cipher);

    return instance;
  }

  public async digest(input: Uint8Array) {
    const buffer = await crypto.subtle.digest(this.hash, input as BufferSource);

    return new Uint8Array(buffer);
  }
}
