"use strict";
/**
 * JavaScript implementation of the MD5 algorithm.
 * 
 * The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. 
 * MD5 was designed by Ronald Rivest in 1991 to replace an earlier hash function MD4,
 * and was specified in 1992 as RFC 1321. (from Wikipedia)
 * 
 * @link   https://en.wikipedia.org/wiki/MD5
 * @link   https://datatracker.ietf.org/doc/html/rfc1321
 * @file   This file defines the md5 global constant.
 * @author Korosium
 */
const md5 = (() => {

    /**
     * The inner logic of the hash function.
     */
    const logic = (() => {

        /**
         * The initial registers.
         */
        const H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

        /**
         * The round constants.
         */
        const K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];

        /**
         * The per-round shift amounts.
         */
        const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

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
            for (let i = 0; i < retval.length; i++) retval[i] = (slice[i * 4 + 3] << 24) | (slice[i * 4 + 2] << 16) | (slice[i * 4 + 1] << 8) | slice[i * 4];
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
            chunk[chunk.length - 2] = parseInt(hex.substring(8, 16), 16);
            chunk[chunk.length - 1] = parseInt(hex.substring(0, 8), 16);
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
            let r = new Uint32Array(registers);
            for (let i = 0; i < 64; i++) {
                let f, g;
                if (i < 16) {
                    f = (r[1] & r[2]) | ((~r[1]) & r[3]);
                    g = i;
                }
                else if (i >= 16 && i < 32) {
                    f = (r[3] & r[1]) | ((~r[3]) & r[2]);
                    g = (5 * i + 1) % 16;
                }
                else if (i >= 32 && i < 48) {
                    f = r[1] ^ r[2] ^ r[3];
                    g = (3 * i + 5) % 16;
                }
                else {
                    f = r[2] ^ (r[1] | (~r[3]));
                    g = (7 * i) % 16;
                }

                f = f + r[0] + K[i] + chunk[g];
                r[0] = r[3];
                r[3] = r[2];
                r[2] = r[1];
                r[1] = r[1] + rotl(f, S[i % 4 + 4 * ((i / 16) & 0xff)]);
            }
            for (let i = 0; i < r.length; i++) r[i] += registers[i];
            return r;
        };

        /**
         * Convert the registers to a little-endian byte array.
         * 
         * @param {Uint32Array} registers The registers to serialize.
         * 
         * @returns {number[]} The byte array checksum.
         */
        const serialize = registers => {
            let retval = [];
            for (let i = 0; i < registers.length; i++) {
                retval[i * 4] = registers[i] & 0xff;
                retval[i * 4 + 1] = (registers[i] >>> 8) & 0xff;
                retval[i * 4 + 2] = (registers[i] >>> 16) & 0xff;
                retval[i * 4 + 3] = (registers[i] >>> 24) & 0xff;
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