import { CIPHER, Cipher, CipherOptions } from '../interfaces/cipher.interface';
import { WebCryptoCipher } from './web-crypto.service';

export const CipherCreator = {
  async create(cipher: CIPHER, password: string, options?: CipherOptions) {
    let instance: Cipher;

    let ivLength: number | undefined;
    let tagLength: number | undefined;

    if (
      options &&
      options.ivLength !== undefined &&
      options.ivLength !== null
    ) {
      ivLength = options.ivLength;
    }

    if (
      options &&
      options.tagLength !== undefined &&
      options.tagLength !== null
    ) {
      tagLength = options.tagLength;
    }

    switch (cipher) {
      case CIPHER.AES_256_CBC:
        instance = await WebCryptoCipher.create(
          'AES-CBC',
          256,
          password,
          ivLength || 16,
          undefined,
          undefined,
          options
        );
        break;
      case CIPHER.AES_256_GCM:
        instance = await WebCryptoCipher.create(
          'AES-GCM',
          256,
          password,
          ivLength || 12,
          tagLength || 128,
          options?.additionalData,
          options
        );
        break;
      default:
        throw new Error(`${cipher} does not exist.`);
    }

    return instance;
  },
};
