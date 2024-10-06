"use strict";
/**
 * JavaScript implementation of the ChaCha20-Poly1305 algorithm.
 * 
 * ChaCha20-Poly1305 is an authenticated encryption with additional data (AEAD) algorithm, 
 * that combines the ChaCha20 stream cipher with the Poly1305 message authentication code. 
 * Its usage in IETF protocols is standardized in RFC 8439. It has fast software performance, 
 * and without hardware acceleration, is usually faster than AES-GCM. (from Wikipedia)
 * 
 * @link   https://en.wikipedia.org/wiki/ChaCha20-Poly1305
 * @link   https://datatracker.ietf.org/doc/html/rfc8439
 * @file   This file defines the chacha20_poly1305 global constant.
 * @author Korosium
 */
const chacha20_poly1305 = (() => {

    /**
     * The length of the key in bytes.
     */
    const KEY_LENGTH = 32;

    /**
     * The length of the nonce in bytes.
     */
    const NONCE_LENGTH = 12;

    /**
     * The length of the tag in bytes.
     */
    const TAG_LENGTH = 16;

    /**
     * The message to send when the calculated tag and the received tag are not the same.
     */
    const INVALID_TAG_ERROR_MESSAGE = 'The received tag and the calculated tag are not the same. The data is invalid.';

    /**
     * The ChaCha20 primitive, used to encrypt and decrypt the data.
     */
    const chacha20 = (() => {

        /**
         * The size of the state in bytes.
         */
        const STATE_SIZE = 64;

        /**
         * The number of rounds to execute on the state.
         */
        const ROUNDS = 20;

        /**
         * The initial words meaning 'expand 32-byte k' in little-endian.
         */
        const H = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

        /**
         * Execute a quater round on the state by modifing either a set of columns or diagonals.
         * 
         * @param {Uint32Array} state The state to modify.
         * @param {number}      a     The first number to modify.
         * @param {number}      b     The second number to modify.
         * @param {number}      c     The third number to modify.
         * @param {number}      d     The fourth number to modify.
         * 
         * @returns {Uint32Array} The modified state.
         */
        const quarter_round = (state, a, b, c, d) => {
            state[a] += state[b];
            state[d] ^= state[a];
            state[d] = rotl(state[d], 16);

            state[c] += state[d];
            state[b] ^= state[c];
            state[b] = rotl(state[b], 12);

            state[a] += state[b];
            state[d] ^= state[a];
            state[d] = rotl(state[d], 8);

            state[c] += state[d];
            state[b] ^= state[c];
            state[b] = rotl(state[b], 7);

            return state;
        };

        /**
         * Perform two full rounds on the state.
         * 
         * @param {Uint32Array} state The state to modify.
         * 
         * @returns {Uint32Array} The modified state.
         */
        const inner_block = state => {
            state = quarter_round(state, 0, 4, 8, 12);
            state = quarter_round(state, 1, 5, 9, 13);
            state = quarter_round(state, 2, 6, 10, 14);
            state = quarter_round(state, 3, 7, 11, 15);
            state = quarter_round(state, 0, 5, 10, 15);
            state = quarter_round(state, 1, 6, 11, 12);
            state = quarter_round(state, 2, 7, 8, 13);
            state = quarter_round(state, 3, 4, 9, 14);
            return state;
        };

        /**
         * Convert the state to a little-endian byte array.
         * 
         * @param {Uint32Array} state The state to serialize.
         * 
         * @returns {number[]} The resulting byte array.
         */
        const serialize = state => {
            let retval = [];
            for (let i = 0; i < STATE_SIZE / 4; i++) {
                retval[i * 4] = state[i] & 0xff;
                retval[i * 4 + 1] = (state[i] >>> 8) & 0xff;
                retval[i * 4 + 2] = (state[i] >>> 16) & 0xff;
                retval[i * 4 + 3] = (state[i] >>> 24) & 0xff;
            }
            return retval;
        };

        /**
         * Initialize the state using the key, the current counter and the nonce.
         * 
         * @param {number[]} key     The key used for the encryption or the decryption process.
         * @param {number}   counter The current block counter.
         * @param {number[]} nonce   The nonce used for the encryption or the decryption process.
         * 
         * @returns {Uint32Array} The initialized state.
         */
        const init = (key, counter, nonce) => {
            return new Uint32Array([
                H[0], H[1], H[2], H[3],
                to_uint_32(key.slice(0, 4)), to_uint_32(key.slice(4, 8)), to_uint_32(key.slice(8, 12)), to_uint_32(key.slice(12, 16)),
                to_uint_32(key.slice(16, 20)), to_uint_32(key.slice(20, 24)), to_uint_32(key.slice(24, 28)), to_uint_32(key.slice(28, 32)),
                counter, to_uint_32(nonce.slice(0, 4)), to_uint_32(nonce.slice(4, 8)), to_uint_32(nonce.slice(8, 12))
            ]);
        };

        /**
         * Rotate the bits of a number to the left by a set amount.
         * 
         * @param {number} n The number to rotate.
         * @param {number} i The amount of bits to rotate.
         * 
         * @returns {number} The number rotated to the left.
         */
        const rotl = (n, i) => (n << i) | (n >>> (32 - i));

        /**
         * Convert a byte array of length 4 into an unsigned integer.
         * 
         * @param {number[]} bytes The byte array to convert.
         * 
         * @returns {number} The new integer.
         */
        const to_uint_32 = bytes => bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];

        return {

            /**
             * Create a key stream using the key, the counter and the nonce.
             * 
             * @param {number[]} key     The key used for the encryption or the decryption process.
             * @param {number}   counter The current block counter.
             * @param {number[]} nonce   The nonce used for the encryption or the decryption process.
             * 
             * @returns {number[]} The key stream.
             */
            block(key, counter, nonce) {
                const original = init(key, counter, nonce);
                let state = new Uint32Array(original);
                for (let i = 0; i < ROUNDS / 2; i++) state = inner_block(state);
                for (let i = 0; i < STATE_SIZE / 4; i++) state[i] += original[i];
                return serialize(state);
            },

            /**
             * Encrypt or decrypt a byte array using the key, the counter and the nonce.
             * 
             * @param {number[]} key       The key used for the encryption or the decryption process.
             * @param {number}   counter   The initial block counter.
             * @param {number[]} nonce     The nonce used for the encryption or the decryption process.
             * @param {number[]} plaintext The data to process.
             * 
             * @returns {number[]} The processed data.
             */
            encrypt(key, counter, nonce, plaintext) {
                let ciphertext = [];
                for (let i = 0; i < plaintext.length; i += STATE_SIZE) {
                    const stream = this.block(key, counter + i / STATE_SIZE, nonce);
                    plaintext.slice(i, i + STATE_SIZE).map((x, j) => ciphertext.push(x ^ stream[j]));
                }
                return ciphertext;
            }

        }

    })();

    /**
     * The Poly1305 primitive, used to authenticate the data.
     */
    const poly1305 = (() => {

        /**
         * Clamp the first 16 bytes of the key.
         * 
         * @param {number[]} r The first 16 bytes of the key.
         * 
         * @returns {number[]} The clamped 'r'.
         */
        const clamp = r => {
            r[3] &= 15;
            r[7] &= 15;
            r[11] &= 15;
            r[15] &= 15;
            r[4] &= 252;
            r[8] &= 252;
            r[12] &= 252;
            return r;
        };

        /**
         * Convert a little-endian byte array to a bigint.
         * 
         * @param {number[]} n The byte array to convert.
         * 
         * @returns {bigint} The new bigint.
         */
        const le_bytes_to_num = n => {
            let hex = '';
            for (let i = n.length - 1; i >= 0; i--) {
                hex += n[i].toString(16).padStart(2, '0');
            }
            return BigInt('0x' + hex);
        };

        /**
         * Convert a bigint to a little-endian byte array.
         * 
         * @param {bigint} a The bigint to convert.
         * 
         * @returns The new little-endian byte array.
         */
        const num_to_16_le_bytes = a => {
            let hex = a.toString(16).padStart(32, '0');
            let retval = [];
            for (let i = hex.length - 2; i >= 0; i -= 2) {
                retval[retval.length] = parseInt(hex.substring(i, i + 2), 16);
                if (retval.length === TAG_LENGTH) break; // Safety
            }
            return retval;
        };

        return {

            /**
             * Create a one-time key for the MAC function.
             * 
             * @param {number[]} key   The key used for the encryption or the decryption process.
             * @param {number[]} nonce The nonce used for the encryption or the decryption process.
             * 
             * @returns {number[]} The new generated one-time key.
             */
            key_gen(key, nonce) {
                return chacha20.block(key, 0, nonce).slice(0, KEY_LENGTH);
            },

            /**
             * Create a tag for the given data.
             * 
             * @param {number[]} msg The data to authenticate.
             * @param {number[]} key The one-time key.
             * 
             * @returns {number[]} The new generated tag.
             */
            mac(msg, key) {
                let r = le_bytes_to_num(clamp(key.slice(0, 16)));
                let s = le_bytes_to_num(key.slice(16, 32));
                let a = 0n;
                const p = BigInt('0x3fffffffffffffffffffffffffffffffb');
                for (let i = 0; i < msg.length; i += 16) {
                    let n = le_bytes_to_num(msg.slice(i, i + 16).concat(1));
                    a += n;
                    a = (r * a) % p;
                }
                a += s;
                return num_to_16_le_bytes(a);
            }

        }

    })();

    /**
     * Utility functions to convert parameters.
     */
    const parameters = (() => {

        /**
         * Pad a byte array to the desired length.
         * 
         * @param {number[]} bytes  The byte array.
         * @param {number}   length The desired length of the resulting byte array.
         * @param {number}   value  The value to append to the byte array.
         * 
         * @returns {number[]} The padded byte array.
         */
        const pad_bytes = (bytes, length, value) => {
            for (let i = bytes.length; i < length; i++) {
                bytes.push(value);
            }
            return bytes;
        };

        /**
         * Clamp a byte array to a specific length.
         * 
         * @param {number[]} bytes  The byte array.
         * @param {number}   length The desired length of the resulting byte array.
         * 
         * @returns {number[]} The clamped byte array.
         */
        const clamp_bytes = (bytes, length) => {
            if (bytes.length === length) return bytes;
            if (bytes.length < length) return pad_bytes(bytes, length, 0);
            return bytes.slice(0, length);
        };

        /**
         * Pad the key for it to be of right length.
         * 
         * @param {number[]} key The key to pad.
         * 
         * @returns {number[]} The padded key.
         */
        const pad_key = key => {
            return clamp_bytes(key, KEY_LENGTH);
        };

        /**
         * Pad the nonce for it to be of right length.
         * 
         * @param {number[]} nonce The nonce to pad.
         * 
         * @returns {number[]} The padded nonce.
         */
        const pad_nonce = nonce => {
            return clamp_bytes(nonce, NONCE_LENGTH);
        };

        return {

            /**
             * Convert all the parameters to their padded and right type equivalent.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer}             key   The key to convert and pad.
             * @param {number[] | string | Uint8Array | ArrayBuffer}             data  The data to convert.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} nonce The nonce to convert and pad.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} aad   The additional authenticated data to convert.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} tag   The tag to convert.
             * 
             * @returns {{key: number[]; data: number[]; nonce: number[]; aad: number[]; tag: string;}} The converted parameters.
             */
            get_parameters(key, data, nonce = [], aad = [], tag = []) {
                return {
                    key: pad_key(conversion.to_byte(key)),
                    data: conversion.to_byte(data),
                    nonce: pad_nonce(conversion.to_byte(nonce)),
                    aad: conversion.to_byte(aad),
                    tag: conversion.to_hex(tag)
                }
            }

        }

    })();

    /**
     * The algorithm that uses both ChaCha20 and Poly1305.
     */
    const combined = (() => {

        /**
         * Pad a byte array up to 16 bytes. If already of length 16, the array stays the same.
         * 
         * @param {number[]} arr The array to pad.
         * 
         * @returns {number[]} The padded array.
         */
        const pad_16_bytes = arr => {
            let to_pad = 16 - arr.length % 16;
            if (to_pad === 16) to_pad = 0;
            let retval = arr.slice();
            for (let i = 0; i < to_pad; i++) {
                retval[retval.length] = 0;
            }
            return retval;
        };

        /**
         * Convert a number to a 8 bytes little-endian representation of itself.
         * 
         * @param {number} n The number to convert.
         * 
         * @returns {number[]} The little-endian byte array.
         */
        const num_to_8_le_bytes = n => {
            let hex = n.toString(16).padStart(16, '0');
            let retval = [];
            for (let i = hex.length - 2; i >= 0; i -= 2) {
                retval[retval.length] = parseInt(hex.substring(i, i + 2), 16);
            }
            return retval;
        };

        return {

            /**
             * Encrypt some data with the ChaCha20-Poly1305 algorithm.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} key       The key used for the encryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext The data to encrypt.
             * @param {number[] | string | Uint8Array | ArrayBuffer} nonce     The nonce used for the encryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer} aad       The additional authenticated data.
             * 
             * @returns {number[]} The encrypted byte array.
             */
            encrypt(key, plaintext, nonce, aad) {
                const params = parameters.get_parameters(key, plaintext, nonce, aad);
                const one_time_key = primitive.poly1305.key_gen(params.key, params.nonce);
                const ciphertext = primitive.chacha20.encrypt(params.key, 1, params.nonce, params.data);
                const mac_data = pad_16_bytes(params.aad).concat(pad_16_bytes(ciphertext)).concat(num_to_8_le_bytes(params.aad.length)).concat(num_to_8_le_bytes(ciphertext.length));
                const tag = primitive.poly1305.mac(mac_data, one_time_key);
                return params.nonce.concat(tag).concat(ciphertext);
            },

            /**
             * Decrypt some data with the ChaCha20-Poly1305 algorithm.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer} ciphertext The data to decrypt.
             * @param {number[] | string | Uint8Array | ArrayBuffer} aad        The additional authenticated data.
             * 
             * @returns {number[]} The decrypted byte array.
             */
            decrypt(key, ciphertext, aad) {
                const params = parameters.get_parameters(key, ciphertext.slice(NONCE_LENGTH + TAG_LENGTH), ciphertext.slice(0, NONCE_LENGTH), aad, ciphertext.slice(NONCE_LENGTH, NONCE_LENGTH + TAG_LENGTH));
                const one_time_key = primitive.poly1305.key_gen(params.key, params.nonce);
                const mac_data = pad_16_bytes(params.aad).concat(pad_16_bytes(params.data)).concat(num_to_8_le_bytes(params.aad.length)).concat(num_to_8_le_bytes(params.data.length));
                const tag = conversion.to_hex(primitive.poly1305.mac(mac_data, one_time_key));
                if (params.tag === tag) {
                    return primitive.chacha20.encrypt(params.key, 1, params.nonce, params.data);
                }
                else {
                    throw new Error(INVALID_TAG_ERROR_MESSAGE);
                }
            }

        }

    })();

    /**
     * All the available encryption encoding.
     */
    const encrypt = (() => {

        return {

            /**
             * Encrypt some data with the ChaCha20-Poly1305 algorithm.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer}             key                The key used for the encryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext          The data to encrypt.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [nonce = number[]] The nonce used for the encryption process. A random nonce is generated by default.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]]   The additional authenticated data, if needed.
             * 
             * @returns {number[]} The ciphertext byte array.
             */
            array(key, plaintext, nonce = utility.generate_nonce(), aad = []) {
                return combined.encrypt(key, plaintext, nonce, aad);
            },

            /**
             * Encrypt some data with the ChaCha20-Poly1305 algorithm.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer}             key                The key used for the encryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext          The data to encrypt.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [nonce = number[]] The nonce used for the encryption process. A random nonce is generated by default.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]]   The additional authenticated data, if needed.
             * 
             * @returns {string} The ciphertext hex string.
             */
            hex(key, plaintext, nonce = utility.generate_nonce(), aad = []) {
                return conversion.to_hex(this.array(key, plaintext, nonce, aad));
            },

            /**
             * Encrypt some data with the ChaCha20-Poly1305 algorithm.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer}             key                The key used for the encryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext          The data to encrypt.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [nonce = number[]] The nonce used for the encryption process. A random nonce is generated by default.
             * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]]   The additional authenticated data, if needed.
             * 
             * @returns {string} The ciphertext Base64 string.
             */
            base64(key, plaintext, nonce = utility.generate_nonce(), aad = []) {
                return conversion.to_base64(this.array(key, plaintext, nonce, aad));
            }

        }

    })();

    /**
     * All the available decryption encoding.
     */
    const decrypt = (() => {

        /**
         * All the available byte array decryption encoding.
         */
        const array = (() => {

            return {

                /**
                 * Decrypt a ciphertext byte array with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {number[]}                                                 ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {number[]} The byte array plaintext.
                 */
                to_array(key, ciphertext, aad = []) {
                    return combined.decrypt(key, ciphertext, aad);
                },

                /**
                 * Decrypt a ciphertext byte array with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {number[]}                                                 ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The hex string plaintext.
                 */
                to_hex(key, ciphertext, aad = []) {
                    return conversion.to_hex(this.to_array(key, ciphertext, aad));
                },

                /**
                 * Decrypt a ciphertext byte array with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {number[]}                                                 ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The Base64 string plaintext.
                 */
                to_base64(key, ciphertext, aad = []) {
                    return conversion.to_base64(this.to_array(key, ciphertext, aad));
                },

                /**
                 * Decrypt a ciphertext byte array with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {number[]}                                                 ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The UTF-8 string plaintext.
                 */
                to_utf8(key, ciphertext, aad = []) {
                    return conversion.to_utf8(this.to_array(key, ciphertext, aad));
                }

            }

        })();

        /**
         * All the available hex string decryption encoding.
         */
        const hex = (() => {

            return {

                /**
                 * Decrypt a ciphertext hex string with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {string}                                                   ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {number[]} The byte array plaintext.
                 */
                to_array(key, ciphertext, aad = []) {
                    return combined.decrypt(key, conversion.from_hex(ciphertext), aad);
                },

                /**
                 * Decrypt a ciphertext hex string with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {string}                                                   ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The hex string plaintext.
                 */
                to_hex(key, ciphertext, aad = []) {
                    return conversion.to_hex(this.to_array(key, ciphertext, aad));
                },

                /**
                 * Decrypt a ciphertext hex string with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {string}                                                   ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The Base64 string plaintext.
                 */
                to_base64(key, ciphertext, aad = []) {
                    return conversion.to_base64(this.to_array(key, ciphertext, aad));
                },

                /**
                 * Decrypt a ciphertext hex string with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {string}                                                   ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The UTF-8 string plaintext.
                 */
                to_utf8(key, ciphertext, aad = []) {
                    return conversion.to_utf8(this.to_array(key, ciphertext, aad));
                }

            }

        })();

        /**
         * All the available Base64 string decryption encoding.
         */
        const base64 = (() => {

            return {

                /**
                 * Decrypt a ciphertext Base64 string with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {string}                                                   ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {number[]} The byte array plaintext.
                 */
                to_array(key, ciphertext, aad = []) {
                    return combined.decrypt(key, conversion.from_base64(ciphertext), aad);
                },

                /**
                 * Decrypt a ciphertext Base64 string with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {string}                                                   ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The hex string plaintext.
                 */
                to_hex(key, ciphertext, aad = []) {
                    return conversion.to_hex(this.to_array(key, ciphertext, aad));
                },

                /**
                 * Decrypt a ciphertext Base64 string with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {string}                                                   ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The Base64 string plaintext.
                 */
                to_base64(key, ciphertext, aad = []) {
                    return conversion.to_base64(this.to_array(key, ciphertext, aad));
                },

                /**
                 * Decrypt a ciphertext Base64 string with the ChaCha20-Poly1305 algorithm.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the decryption process.
                 * @param {string}                                                   ciphertext       The ciphertext to decrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [aad = number[]] The additional authenticated data, if needed.
                 * 
                 * @returns {string} The UTF-8 string plaintext.
                 */
                to_utf8(key, ciphertext, aad = []) {
                    return conversion.to_utf8(this.to_array(key, ciphertext, aad));
                }

            }

        })();

        return {

            array: array,
            hex: hex,
            base64: base64

        }

    })();

    /**
     * Utility functions used for conversions.
     */
    const conversion = (() => {

        return {

            /**
             * Convert the input to a byte array.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The input to convert.
             * 
             * @returns {number[]} The byte array.
             */
            to_byte(data) {
                const type = Object.prototype.toString.call(data);
                switch (type) {
                    case '[object Array]': return data.slice();
                    case '[object String]': return [].slice.call(new TextEncoder().encode(data));
                    case '[object Uint8Array]': return [].slice.call(data);
                    case '[object ArrayBuffer]': return [].slice.call(new Uint8Array(data));
                    default: throw new Error(`Invalid data type "${type}" provided.`);
                }
            },

            /**
             * Convert a byte array to an hex string.
             * 
             * @param {number[]} arr The byte array to convert.
             * 
             * @returns {string} The new hex string.
             */
            to_hex(arr) {
                return arr.map(x => x.toString(16).padStart(2, '0')).join('');
            },

            /**
             * Convert a byte array to a Base64 string.
             * 
             * @param {number[]} arr The byte array to convert.
             * 
             * @returns {string} The new Base64 string.
             */
            to_base64(arr) {
                return btoa(arr.map(x => String.fromCharCode(x)).join(''));
            },

            /**
             * Convert a byte array to a UTF-8 string.
             * 
             * @param {number[]} arr The byte array to convert.
             * 
             * @returns {string} The new UTF-8 string.
             */
            to_utf8(arr) {
                return new TextDecoder().decode(new Uint8Array(arr).buffer);
            },

            /**
             * Convert an hex string to a byte array.
             * 
             * @param {string} s The hex string to convert.
             * 
             * @returns {number[]} The new byte array.
             */
            from_hex(s) {
                let retval = [];
                for (let i = 0; i < s.length; i += 2) retval.push(parseInt(s.substring(i, i + 2), 16));
                return retval;
            },

            /**
             * Convert a Base64 string to a byte array.
             * 
             * @param {string} s The Base64 string to convert.
             * 
             * @returns {number[]} The new byte array.
             */
            from_base64(s) {
                return atob(s).split('').map(x => x.charCodeAt());
            }

        }

    })();

    /**
     * All the primitives used in the combined protocol.
     */
    const primitive = (() => {

        return {

            chacha20: chacha20,
            poly1305: poly1305

        }

    })();

    /**
     * Some utility functions.
     */
    const utility = (() => {

        return {

            /**
             * Generate a new nonce.
             * 
             * @returns {number[]} The new generated nonce.
             */
            generate_nonce() {
                const timestamp = Date.now().toString(16).padStart(KEY_LENGTH * 2, '0');
                let key = [];
                for (let i = 0; i < timestamp.length; i += 2) key.push(parseInt(timestamp.slice(i, i + 2), 16));
                const counter = 0xffffffff;
                const nonce = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
                return primitive.chacha20.block(key, counter, nonce).slice(0, NONCE_LENGTH);
            }

        }

    })();

    return {

        encrypt: encrypt,
        decrypt: decrypt,
        primitive: primitive,

    }

})();