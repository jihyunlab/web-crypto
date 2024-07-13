# @jihyunlab/web-crypto

[![Version](https://img.shields.io/npm/v/@jihyunlab/web-crypto.svg?style=flat-square)](https://www.npmjs.com/package/@jihyunlab/web-crypto?activeTab=versions) [![Downloads](https://img.shields.io/npm/dt/@jihyunlab/web-crypto.svg?style=flat-square)](https://www.npmjs.com/package/@jihyunlab/web-crypto) [![Last commit](https://img.shields.io/github/last-commit/jihyunlab/web-crypto.svg?style=flat-square)](https://github.com/jihyunlab/web-crypto/graphs/commit-activity) [![License](https://img.shields.io/github/license/jihyunlab/web-crypto.svg?style=flat-square)](https://github.com/jihyunlab/web-crypto/blob/master/LICENSE) [![Linter](https://img.shields.io/badge/linter-eslint-blue?style=flat-square)](https://eslint.org) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)\
[![Build](https://github.com/jihyunlab/web-crypto/actions/workflows/build.yml/badge.svg)](https://github.com/jihyunlab/web-crypto/actions/workflows/build.yml) [![Lint](https://github.com/jihyunlab/web-crypto/actions/workflows/lint.yml/badge.svg)](https://github.com/jihyunlab/web-crypto/actions/workflows/lint.yml) [![codecov](https://codecov.io/gh/jihyunlab/web-crypto/graph/badge.svg?token=UW73ZNZY03)](https://codecov.io/gh/jihyunlab/web-crypto)

@jihyunlab/web-crypto can be used by web applications such as React.

@jihyunlab/web-crypto was developed to enhance the convenience of implementing cryptographic functionalities in web applications.

The encryption function is implemented with [Web Crypto API](https://nodejs.org/api/webcrypto.html) in Node.js and provides encryption for AES 256 CBC and AES 256 GCM.

## Installation

```bash
npm i @jihyunlab/web-crypto
```

## Usage

You can easily encrypt and decrypt data with a simple method.

```
import { createCipher } from '@jihyunlab/web-crypto';

const cipher = await createCipher(
  'aes-256-gcm' /* aes-256-cbc, aes-256-gcm */,
  'your secret key'
);

const encrypted = await cipher.encrypt('jihyunlab');
console.log(encrypted); // Uint8Array(37)[51, 174, 20, 84, 12, 141, 173, 206, 249, 11, 59, 112, 88, 223, 163, 211, 128, 234, 102, 116, 16, 224, 175, 45, 46, 52, 186, 141, 15, 243, 9, 120, 64, 27, 135, 169, 65]

const decrypted = await cipher.decrypt(encrypted);
console.log(decrypted); // Uint8Array(9)[106, 105, 104, 121, 117, 110, 108, 97, 98]
```

Provides encryption functionality for Uint8Array data.

```
const encrypted = await cipher.encrypt(
  new Uint8Array([106, 105, 104, 121, 117, 110, 108, 97, 98])
);
console.log(encrypted); // Uint8Array(37)[185, 95, 254, 103, 109, 250, 109, 50, 8, 218, 251, 74, 215, 108, 74, 86, 177, 82, 144, 154, 156, 120, 128, 169, 112, 236, 153, 23, 253, 164, 238, 159, 236, 17, 85, 26, 75]

const decrypted = await cipher.decrypt(encrypted);
console.log(decrypted); // Uint8Array(9)[106, 105, 104, 121, 117, 110, 108, 97, 98]
```

## @jihyunlab/web-buffer

You can install [@jihyunlab/web-buffer](https://www.npmjs.com/package/@jihyunlab/web-buffer) to perform additional data conversions.

```
npm i @jihyunlab/web-buffer
```

```
import { WebBuffer } from '@jihyunlab/web-buffer';

const buffer = WebBuffer.from(
  new Uint8Array([106, 105, 104, 121, 117, 110, 108, 97, 98]),
  'uint8array' /* hex, base64, base64url, utf8, uint8array */
);

const utf8 = buffer.toString('utf8');
console.log(utf8); // jihyunlab
```

## @jihyunlab/crypto

[@jihyunlab/crypto](https://www.npmjs.com/package/@jihyunlab/crypto) implements encryption functionalities for Node.js applications using the same interface as @jihyunlab/web-crypto.

Consider using @jihyunlab/crypto for decrypting encrypted data from @jihyunlab/web-crypto in Node.js applications, or vice versa.

## Credits

Authored and maintained by JihyunLab <<info@jihyunlab.com>>

## License

Open source [licensed as MIT](https://github.com/jihyunlab/web-crypto/blob/master/LICENSE).
