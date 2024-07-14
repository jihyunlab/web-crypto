/**
 * @jest-environment jsdom
 */
import { WebCryptoCipher } from '../../src/ciphers/web-crypto.cipher';
import { WebBuffer } from '@jihyunlab/web-buffer';
import { KeyHelper } from '../../src/helpers/key.helper';

describe('Web crypto cipher', () => {
  test(`Negative: encrypt() - key does not exist.`, async () => {
    const spy = jest.spyOn(KeyHelper as any, 'pbkdf2');
    spy.mockImplementation(() => {
      return undefined;
    });

    const cipher = await WebCryptoCipher.create('AES-GCM', 256, 'password', 12);

    expect(async () => {
      await cipher.encrypt('text');
    }).rejects.toThrow(Error('key does not exist.'));

    spy.mockReset();
    spy.mockRestore();
  });

  test(`Negative: decrypt() - key does not exist.`, async () => {
    const spy = jest.spyOn(KeyHelper as any, 'pbkdf2');
    spy.mockImplementation(() => {
      return undefined;
    });

    const cipher = await WebCryptoCipher.create('AES-GCM', 256, 'password', 12);

    expect(async () => {
      await cipher.decrypt('text');
    }).rejects.toThrow(Error('key does not exist.'));

    spy.mockReset();
    spy.mockRestore();
  });

  test(`Negative: decrypt() - key does not exist.`, async () => {
    const cipher = await WebCryptoCipher.create('AES-GCM', 256, 'password', 12);

    expect(async () => {
      await cipher.decrypt('0');
    }).rejects.toThrow(Error('invalid text.'));
  });

  test(`Negative: decrypt() - iv conversion failed.`, async () => {
    const spy = jest.spyOn(WebBuffer as any, 'from');
    spy.mockImplementation(() => {
      return {
        toUint8Array() {
          return null;
        },
      };
    });

    const cipher = await WebCryptoCipher.create('AES-GCM', 256, 'password', 12);

    expect(async () => {
      await cipher.decrypt('00000000000000000000000000000000');
    }).rejects.toThrow(Error('iv conversion failed.'));

    spy.mockReset();
    spy.mockRestore();
  });

  test(`Negative: decrypt() - ciphertext conversion failed.`, async () => {
    const spy = jest.spyOn(WebBuffer as any, 'from');
    spy
      .mockImplementationOnce(() => {
        return {
          toUint8Array() {
            return new Uint8Array(0);
          },
        };
      })
      .mockImplementationOnce(() => {
        return {
          toUint8Array() {
            return null;
          },
        };
      });

    const cipher = await WebCryptoCipher.create('AES-GCM', 256, 'password', 12);

    expect(async () => {
      await cipher.decrypt('00000000000000000000000000000000');
    }).rejects.toThrow(Error('ciphertext conversion failed.'));

    spy.mockReset();
    spy.mockRestore();
  });
});
