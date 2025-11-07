import { Cipher, CipherOptions } from '../interfaces/cipher.interface';
import { KeyHelper } from '../helpers/key.helper';
import { WebBuffer } from '@jihyunlab/web-buffer';

const crypto = globalThis.crypto;

export class WebCryptoCipher implements Cipher {
  private readonly cipher: string;
  private readonly ivLength: number;
  private readonly key: CryptoKey;
  private readonly tagLength?: number;
  private readonly additionalData?: Uint8Array;

  private constructor(
    cipher: string,
    key: CryptoKey,
    ivLength: number,
    tagLength?: number,
    additionalData?: Uint8Array
  ) {
    this.cipher = cipher;
    this.key = key;
    this.ivLength = ivLength;
    this.tagLength = tagLength;
    this.additionalData = additionalData;
  }

  public static async create(
    cipher: string,
    length: number,
    password: string,
    ivLength: number,
    tagLength?: number,
    additionalData?: Uint8Array,
    options?: CipherOptions
  ) {
    let salt = '';
    let iterations = 128;

    if (options && options.salt) {
      salt = options.salt;
    }

    if (
      options &&
      options.iterations !== undefined &&
      options.iterations !== null
    ) {
      iterations = options.iterations;
    }

    const key = await KeyHelper.pbkdf2(
      cipher,
      length,
      password,
      salt,
      iterations
    );

    const instance = new WebCryptoCipher(
      cipher,
      key,
      ivLength,
      tagLength,
      additionalData
    );

    return instance;
  }

  private params(
    name: string,
    iv: Uint8Array,
    tagLength?: number,
    additionalData?: Uint8Array
  ) {
    const params: {
      name: string;
      iv: Uint8Array;
      tagLength?: number;
      additionalData?: Uint8Array;
    } = {
      name: name,
      iv: iv,
    };

    if (tagLength !== undefined && tagLength !== null) {
      params['tagLength'] = tagLength;
    }

    if (additionalData) {
      params['additionalData'] = additionalData;
    }

    return params;
  }

  public async encrypt(text: string | Uint8Array) {
    if (!this.key) {
      throw new Error('key does not exist.');
    }

    let textArray: Uint8Array;

    if (typeof text === 'string') {
      const textEncoder = new TextEncoder();
      textArray = textEncoder.encode(text);
    } else {
      textArray = text;
    }

    const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));

    const ciphertext = await crypto.subtle.encrypt(
      this.params(this.cipher, iv, this.tagLength, this.additionalData),
      this.key,
      textArray as unknown as BufferSource
    );

    const uint8Array = new Uint8Array(ciphertext);

    const encrypted = new Uint8Array(iv.length + uint8Array.length);
    encrypted.set(iv, 0);
    encrypted.set(uint8Array, iv.length);

    return encrypted;
  }

  public async decrypt(text: string | Uint8Array) {
    if (!this.key) {
      throw new Error('key does not exist.');
    }

    let iv: Uint8Array | null;
    let ciphertext: Uint8Array | null;

    if (typeof text === 'string') {
      if (text.length <= this.ivLength * 2) {
        throw new Error('invalid text.');
      }

      iv = WebBuffer.from(
        text.substring(0, this.ivLength * 2),
        'hex'
      ).toUint8Array();

      ciphertext = WebBuffer.from(
        text.substring(this.ivLength * 2),
        'hex'
      ).toUint8Array();
    } else {
      iv = text.subarray(0, this.ivLength);
      ciphertext = text.subarray(this.ivLength);
    }

    if (!iv) {
      throw new Error('iv conversion failed.');
    }

    if (!ciphertext) {
      throw new Error('ciphertext conversion failed.');
    }

    const decrypted = await crypto.subtle.decrypt(
      this.params(this.cipher, iv, this.tagLength, this.additionalData),
      this.key,
      ciphertext as unknown as BufferSource
    );

    return new Uint8Array(decrypted);
  }
}
