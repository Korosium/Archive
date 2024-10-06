"use strict";
/**
 * JavaScript implementation of the MD4 algorithm.
 * 
 * The MD4 Message-Digest Algorithm is a cryptographic hash function developed 
 * by Ronald Rivest in 1990. The digest length is 128 bits. The algorithm has 
 * influenced later designs, such as the MD5, SHA-1 and RIPEMD algorithms. 
 * The initialism "MD" stands for "Message Digest". (from Wikipedia)
 * 
 * @link   https://en.wikipedia.org/wiki/MD4
 * @link   https://datatracker.ietf.org/doc/html/rfc1320
 * @file   This file defines the md4 global constant.
 * @author Korosium
 */
const md4 = (() => {

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
        const K = [0x5a827999, 0x6ed9eba1];

        /**
         * The per-round shift amounts.
         */
        const S = [3, 7, 11, 19, 3, 5, 9, 13, 3, 9, 11, 15];

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
            for (let i = 0; i < 48; i++) {
                let f, g, k;
                if (i < 16) {
                    f = (r[1] & r[2]) | ((~r[1]) & r[3]);
                    g = i;
                    k = 0;
                }
                else if (i >= 16 && i < 32) {
                    f = (r[1] & r[2]) | (r[1] & r[3]) | (r[2] & r[3]);
                    g = calcG(i, [0, 1, 2, 3]);
                    k = K[0];
                }
                else {
                    f = r[1] ^ r[2] ^ r[3];
                    g = calcG(i, [0, 2, 1, 3]);
                    k = K[1];
                }

                f = f + r[0] + k + chunk[g];
                r[0] = r[3];
                r[3] = r[2];
                r[2] = r[1];
                r[1] = rotl(f, S[i % 4 + 4 * ((i / 16) & 0xff)]);
            }
            for (let i = 0; i < r.length; i++) r[i] += registers[i];
            return r;
        };

        /**
         * Calculate the G value for the 2nd and 3rd round of the compression function.
         * 
         * @param {number} i The current index.
         * @param {number} m The matrix to calculate G.
         * 
         * @returns {number} The G value.
         */
        const calcG = (i, m) => 4 * m[i % 4] + m[(i % 16) / 4 & 0xff];

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