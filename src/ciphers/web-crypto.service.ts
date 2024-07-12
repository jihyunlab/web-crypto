import { Cipher, Options } from '../interfaces/cipher.interface';
import { Key } from '../helpers/key.helper';
import { WebArrayConverter } from '@jihyunlab/web-array-converter';

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
    options?: Options
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

    const key = await Key.pbkdf2(cipher, length, password, salt, iterations);

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
      textArray
    );

    if (typeof text === 'string') {
      return (
        WebArrayConverter.from(iv).toString('hex') +
        WebArrayConverter.from(new Uint8Array(ciphertext)).toString('hex')
      );
    } else {
      const uint8Array = new Uint8Array(ciphertext);

      const encryptedArray = new Uint8Array(iv.length + uint8Array.length);
      encryptedArray.set(iv, 0);
      encryptedArray.set(uint8Array, iv.length);

      return encryptedArray;
    }
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

      iv = WebArrayConverter.from(
        text.substring(0, this.ivLength * 2),
        'hex'
      ).toUint8Array();

      ciphertext = WebArrayConverter.from(
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

    const plaintext = await crypto.subtle.decrypt(
      this.params(this.cipher, iv, this.tagLength, this.additionalData),
      this.key,
      ciphertext
    );

    if (typeof text === 'string') {
      return new TextDecoder().decode(plaintext);
    } else {
      return new Uint8Array(plaintext);
    }
  }
}
