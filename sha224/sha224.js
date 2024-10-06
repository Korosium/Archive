"use strict";
/**
 * JavaScript implementation of the SHA-224 algorithm.
 * 
 * SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by 
 * the United States National Security Agency (NSA) and first published in 2001.
 * They are built using the Merkle–Damgård construction, from a one-way compression function 
 * itself built using the Davies–Meyer structure from a specialized block cipher. (from Wikipedia)
 * 
 * @link   https://en.wikipedia.org/wiki/SHA-2
 * @link   https://datatracker.ietf.org/doc/html/rfc6234
 * @file   This file defines the sha224 global constant.
 * @author Korosium
 */
const sha224 = (() => {

    /**
     * The inner logic of the hash function.
     */
    const logic = (() => {

        /**
         * The initial registers.
         */
        const H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];

        /**
         * The round constants.
         */
        const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

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
            for (let i = 0; i < 64; i++) {
                const temp1 = r[7] + us1(r[4]) + ch(r[4], r[5], r[6]) + K[i] + w[i];
                const temp2 = us0(r[0]) + maj(r[0], r[1], r[2]);
                r[7] = r[6];
                r[6] = r[5];
                r[5] = r[4];
                r[4] = r[3] + temp1;
                r[3] = r[2];
                r[2] = r[1];
                r[1] = r[0];
                r[0] = temp1 + temp2;
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
            let retval = new Uint32Array(64);
            for (let i = 0; i < 64; i++) {
                if (i < 16) retval[i] = chunk[i];
                else retval[i] = retval[i - 16] + ls0(retval[i - 15]) + retval[i - 7] + ls1(retval[i - 2]);
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
            for (let i = 0; i < registers.length - 1; i++) {
                retval[i * 4] = (registers[i] >>> 24) & 0xff;
                retval[i * 4 + 1] = (registers[i] >>> 16) & 0xff;
                retval[i * 4 + 2] = (registers[i] >>> 8) & 0xff;
                retval[i * 4 + 3] = registers[i] & 0xff;
            }
            return retval;
        };

        /**
         * Rotate the bits of a number to the right by a set amount.
         * 
         * @param {number} n The number to rotate.
         * @param {number} i The amount of bits to rotate.
         * 
         * @returns {number} The number rotated to the right.
         */
        const rotr = (n, i) => (n >>> i) | (n << (32 - i));

        /**
         * The lower sigma zero function.
         * 
         * @param {number} n The register to process.
         * 
         * @returns {number} The modified register.
         */
        const ls0 = n => rotr(n, 7) ^ rotr(n, 18) ^ (n >>> 3);

        /**
         * The lower sigma one function.
         * 
         * @param {number} n The register to process.
         * 
         * @returns {number} The modified register.
         */
        const ls1 = n => rotr(n, 17) ^ rotr(n, 19) ^ (n >>> 10);

        /**
         * The upper sigma zero function.
         * 
         * @param {number} n The register to process.
         * 
         * @returns {number} The modified register.
         */
        const us0 = n => rotr(n, 2) ^ rotr(n, 13) ^ rotr(n, 22);

        /**
         * The upper sigma one function.
         * 
         * @param {number} n The register to process.
         * 
         * @returns {number} The modified register.
         */
        const us1 = n => rotr(n, 6) ^ rotr(n, 11) ^ rotr(n, 25);

        /**
         * The choice function.
         * 
         * @param {number} x The first number.
         * @param {number} y The second number.
         * @param {number} z The third number.
         * 
         * @returns The new number.
         */
        const ch = (x, y, z) => (x & y) ^ ((~x) & z);

        /**
         * The majority function.
         * 
         * @param {number} x The first number.
         * @param {number} y The second number.
         * @param {number} z The third number.
         * 
         * @returns The new number.
         */
        const maj = (x, y, z) => (x & y) ^ (x & z) ^ (y & z);

        return {

            /**
             * Process the data and hash it.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The data to hash.
             * 
             * @returns {number[]} The byte array checksum.
             */
            process(data){
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
                return conversion.to_hex(logic.process(data));
            },

            /**
             * Hash the input data to get it's Base64 string checksum.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The data to hash.
             * 
             * @returns {string} The Base64 string checksum.
             */
            base64(data) {
                return conversion.to_base64(logic.process(data));
            }

        }

    })();

    return {

        hash: hash

    }

})();