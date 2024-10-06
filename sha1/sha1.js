"use strict";
/**
 * JavaScript implementation of the SHA-1 algorithm.
 * 
 * In cryptography, SHA-1 (Secure Hash Algorithm 1) is a hash function which takes an input 
 * and produces a 160-bit (20-byte) hash value known as a message digest – typically rendered 
 * as 40 hexadecimal digits. It was designed by the United States National Security Agency, 
 * and is a U.S. Federal Information Processing Standard. The algorithm has been cryptographically 
 * broken but is still widely used. (from Wikipedia)
 * 
 * @link   https://en.wikipedia.org/wiki/SHA-1
 * @link   https://datatracker.ietf.org/doc/html/rfc3174
 * @file   This file defines the sha1 global constant.
 * @author Korosium
 */
const sha1 = (() => {

    /**
     * The inner logic of the hash function.
     */
    const logic = (() => {

        /**
         * The initial registers.
         */
        const H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

        /**
         * The round constants.
         */
        const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

        /**
         * Transform the registers by processing a slice of the data to hash.
         * 
         * @param {Uint32Array} registers The registers to transform.
         * @param {number[]}    slice     The slice to process.
         * @param {number}      length    The total length of the data.
         * 
         * @returns {Uint32Array} The transformed registers.
         */
        const transform = (registers, slice, length) => {
            if (slice.length === 64) return compress(registers, convert(slice));
            else if (slice.length >= 56) return compress(compress(registers, convert(pad(slice))), append(convert(pad([], 0)), length));
            else return compress(registers, append(convert(pad(slice)), length));
        };

        /**
         * Pad the slice for it to be the same size as the state.
         * 
         * @param {number[]}           slice          The slice to pad.
         * @param {number | undefined} [first = 0x80] The first byte to append.
         * 
         * @returns {number[]} The padded slice.
         */
        const pad = (slice, first = 0x80) => {
            slice[slice.length] = first;
            for (let i = slice.length; i < 64; i++) slice[i] = 0;
            return slice;
        };

        /**
         * Convert the slice to a chunk.
         * 
         * @param {number[]} slice The slice to convert.
         * 
         * @returns {Uint32Array} The new chunk.
         */
        const convert = slice => {
            let retval = new Uint32Array(slice.length / 4);
            for (let i = 0; i < retval.length; i++) retval[i] = (slice[i * 4] << 24) | (slice[i * 4 + 1] << 16) | (slice[i * 4 + 2] << 8) | slice[i * 4 + 3];
            return retval;
        };

        /**
         * Append the total length of the data in bits at the end of the last chunk.
         * 
         * @param {Uint32Array} chunk  The chunk to append the length to.
         * @param {number}      length The total length of the data.
         * 
         * @returns {Uint32Array} The chunk with the length of the data at the end.
         */
        const append = (chunk, length) => {
            const hex = (length * 8).toString(16).padStart(16, "0");
            chunk[chunk.length - 2] = parseInt(hex.substring(0, 8), 16);
            chunk[chunk.length - 1] = parseInt(hex.substring(8, 16), 16);
            return chunk;
        };

        /**
         * Compress the new chunk with the registers.
         * 
         * @param {Uint32Array} registers The registers to compress.
         * @param {Uint32Array} chunk     The chunk to compress.
         * 
         * @returns {Uint32Array} The compressed registers.
         */
        const compress = (registers, chunk) => {
            const w = init(chunk);
            let r = new Uint32Array(registers);
            for (let i = 0; i < 80; i++) {
                let f;
                if (i < 20) f = (r[1] & r[2]) | ((~r[1]) & r[3]);
                else if (i >= 40 && i < 60) f = (r[1] & r[2]) | (r[1] & r[3]) | (r[2] & r[3]);
                else f = r[1] ^ r[2] ^ r[3];
                const temp = rotl(r[0], 5) + f + r[4] + K[(i / 20) & 0xff] + w[i];
                r[4] = r[3];
                r[3] = r[2];
                r[2] = rotl(r[1], 30);
                r[1] = r[0];
                r[0] = temp;
            }
            for (let i = 0; i < r.length; i++) r[i] += registers[i];
            return r;
        };

        /**
         * Initialize the current chunk by extending it.
         * 
         * @param {Uint32Array} chunk The chunk to extend.
         * 
         * @returns {Uint32Array} The extended chunk.
         */
        const init = chunk => {
            let retval = new Uint32Array(80);
            for (let i = 0; i < 80; i++) {
                if (i < 16) retval[i] = chunk[i];
                else retval[i] = rotl(retval[i - 3] ^ retval[i - 8] ^ retval[i - 14] ^ retval[i - 16], 1);
            }
            return retval;
        };

        /**
         * Convert the registers to a big-endian byte array.
         * 
         * @param {Uint32Array} registers The registers to serialize.
         * 
         * @returns {number[]} The byte array checksum.
         */
        const serialize = registers => {
            let retval = [];
            for (let i = 0; i < registers.length; i++) {
                retval[i * 4] = (registers[i] >>> 24) & 0xff;
                retval[i * 4 + 1] = (registers[i] >>> 16) & 0xff;
                retval[i * 4 + 2] = (registers[i] >>> 8) & 0xff;
                retval[i * 4 + 3] = registers[i] & 0xff;
            }
            return retval;
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

        return {

            /**
             * Process the data and hash it.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The data to hash.
             * 
             * @returns {number[]} The byte array checksum.
             */
            process(data) {
                const bytes = conversion.to_byte(data);
                let registers = new Uint32Array(H);
                for (let i = 0; i <= bytes.length; i += 64) registers = transform(registers, bytes.slice(i, i + 64), bytes.length);
                return serialize(registers);
            }

        }

    })();

    /**
     * Utility functions for conversions.
     */
    const conversion = (() => {

        return {

            /**
             * Convert the data to a byte array.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The data to convert.
             * 
             * @returns {number[]} The byte array.
             */
            to_byte(data) {
                const type = Object.prototype.toString.call(data);
                switch (type) {
                    case "[object Array]": return data.slice();
                    case "[object String]": return [].slice.call(new TextEncoder().encode(data));
                    case "[object Uint8Array]": return [].slice.call(data);
                    case "[object ArrayBuffer]": return [].slice.call(new Uint8Array(data));
                    default: throw new Error(`Invalid data type "${type}" provided.`);
                }
            },

            /**
             * Convert a byte array to an hex string.
             * 
             * @param {number[]} arr The byte array to convert.
             * 
             * @returns {string} The hex string.
             */
            to_hex(arr) {
                return arr.map(x => x.toString(16).padStart(2, '0')).join('');
            },

            /**
             * Convert a byte array to a Base64 string.
             * 
             * @param {number[]} arr The byte array to convert.
             * 
             * @returns {string} The Base64 string.
             */
            to_base64(arr) {
                return btoa(arr.map(x => String.fromCharCode(x)).join(''));
            }

        }

    })();

    /**
     * The available hash encoding.
     */
    const hash = (() => {

        return {

            /**
             * Hash the input data to get it's byte array checksum.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The data to hash.
             * 
             * @returns {number[]} The byte array checksum.
             */
            array(data) {
                return logic.process(data);
            },

            /**
             * Hash the input data to get it's hex string checksum.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The data to hash.
             * 
             * @returns {string} The hex string checksum.
             */
            hex(data) {
                return conversion.to_hex(this.array(data));
            },

            /**
             * Hash the input data to get it's Base64 string checksum.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The data to hash.
             * 
             * @returns {string} The Base64 string checksum.
             */
            base64(data) {
                return conversion.to_base64(this.array(data));
            }

        }

    })();

    return {

        hash: hash

    }

})();