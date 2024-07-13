/**
 * @jest-environment jsdom
 */
import { createCipher } from '../src/index';

describe('Web crypto', () => {
  test(`Positive: CIPHER.AES_256_CBC`, async () => {
    let cipher = await createCipher('aes-256-cbc', 'key');

    const encrypted = await cipher.encrypt('value');

    cipher = await createCipher('aes-256-cbc', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_CBC - options`, async () => {
    let cipher = await createCipher('aes-256-cbc', 'key', {
      salt: 'salt',
      iterations: 128,
      ivLength: 16,
    });

    const encrypted = await cipher.encrypt('value');

    cipher = await createCipher('aes-256-cbc', 'key', {
      salt: 'salt',
      iterations: 128,
      ivLength: 16,
    });
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_CBC - uint8array`, async () => {
    let cipher = await createCipher('aes-256-cbc', 'key');

    const encrypted = await cipher.encrypt(new Uint8Array([10, 20, 30, 40]));

    cipher = await createCipher('aes-256-cbc', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([10, 20, 30, 40]));
  });

  test(`Positive: CIPHER.AES_256_CBC - from node crypto`, async () => {
    const encrypted =
      'e057f49f47d57c6ee73443473971b3b05a4f5e3b26285d57b8ef508d914aa1b7';

    const cipher = await createCipher('aes-256-cbc', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_CBC - uint8array - from node crypto`, async () => {
    const encrypted = new Uint8Array([
      46, 39, 190, 251, 94, 5, 235, 33, 169, 195, 60, 21, 56, 214, 114, 228, 84,
      137, 76, 64, 175, 64, 56, 208, 93, 135, 35, 169, 141, 243, 198, 231,
    ]);

    const cipher = await createCipher('aes-256-cbc', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([10, 20, 30, 40]));
  });

  test(`Positive: CIPHER.AES_256_CBC - from web-secure-storage`, async () => {
    const encrypted =
      'e36e4673703230dd1f7e8e2083a934760a6ca0e542a2f7ab9a61ee439601a983bcaacf2e75fb7343914ec30d41b44db4';

    const cipher = await createCipher('aes-256-cbc', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(
      new Uint8Array([
        119, 101, 98, 45, 115, 101, 99, 117, 114, 101, 45, 115, 116, 111, 114,
        97, 103, 101,
      ])
    );
  });

  test(`Positive: CIPHER.AES_256_GCM`, async () => {
    let cipher = await createCipher('aes-256-gcm', 'key');

    const encrypted = await cipher.encrypt('value');

    cipher = await createCipher('aes-256-gcm', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_GCM - options`, async () => {
    let cipher = await createCipher('aes-256-gcm', 'key', {
      salt: 'salt',
      iterations: 128,
      ivLength: 12,
      tagLength: 128,
      additionalData: new Uint8Array([1, 2, 3, 4]),
    });

    const encrypted = await cipher.encrypt('value');

    cipher = await createCipher('aes-256-gcm', 'key', {
      salt: 'salt',
      additionalData: new Uint8Array([1, 2, 3, 4]),
    });
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_GCM - uint8array`, async () => {
    let cipher = await createCipher('aes-256-gcm', 'key');

    const encrypted = await cipher.encrypt(new Uint8Array([10, 20, 30, 40]));

    cipher = await createCipher('aes-256-gcm', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([10, 20, 30, 40]));
  });

  test(`Positive: CIPHER.AES_256_GCM - from node crypto`, async () => {
    const encrypted =
      '9788cd9c3c6a4012da2c359e3b00970ddd4021418c6801ba4eb379a799294d2e61';

    const cipher = await createCipher('aes-256-gcm', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([118, 97, 108, 117, 101]));
  });

  test(`Positive: CIPHER.AES_256_GCM - uint8array - from node crypto`, async () => {
    const encrypted = new Uint8Array([
      10, 99, 0, 243, 129, 25, 201, 1, 238, 83, 115, 136, 72, 207, 243, 139,
      113, 234, 184, 160, 201, 252, 127, 243, 246, 69, 45, 31, 12, 227, 143,
      191,
    ]);

    const cipher = await createCipher('aes-256-gcm', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(new Uint8Array([10, 20, 30, 40]));
  });

  test(`Positive: CIPHER.AES_256_GCM - from web-secure-storage`, async () => {
    const encrypted =
      '5751cc2e9ddeb49c8ba5ed58b7b73a4129606a4249022df3c223ca2ed74557dbbc6f14e82935640dc52b3a70e9c6';

    const cipher = await createCipher('aes-256-gcm', 'key');
    const decrypted = await cipher.decrypt(encrypted);

    expect(decrypted).toStrictEqual(
      new Uint8Array([
        119, 101, 98, 45, 115, 101, 99, 117, 114, 101, 45, 115, 116, 111, 114,
        97, 103, 101,
      ])
    );
  });
});
