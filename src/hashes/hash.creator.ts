import { HASH, Hash } from '../interfaces/hash.interface';
import { WebCryptoHash } from './web-crypto.hash';

export const HashCreator = {
  async create(hash: HASH) {
    let instance: Hash;

    switch (hash) {
      case HASH.SHA_256:
        instance = await WebCryptoHash.create('SHA-256');
        break;
      case HASH.SHA_384:
        instance = await WebCryptoHash.create('SHA-384');
        break;
      default:
        throw new Error(`${hash} does not exist.`);
    }

    return instance;
  },
};
