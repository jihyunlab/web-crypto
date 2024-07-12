export const CIPHER = {
  AES_256_CBC: 'AES-256-CBC',
  AES_256_GCM: 'AES-256-GCM',
} as const;
export type CIPHER = (typeof CIPHER)[keyof typeof CIPHER];

export interface Cipher {
  encrypt: (text: string | Uint8Array) => Promise<Uint8Array>;
  decrypt: (text: string | Uint8Array) => Promise<Uint8Array>;
}

export interface CipherOptions {
  salt?: string;
  iterations?: number;
  ivLength?: number;
  tagLength?: 32 | 64 | 96 | 104 | 112 | 120 | 128;
  additionalData?: Uint8Array;
}
