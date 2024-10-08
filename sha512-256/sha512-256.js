"use strict";
/**
 * JavaScript implementation of the SHA-512/256 algorithm.
 * 
 * SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by 
 * the United States National Security Agency (NSA) and first published in 2001.
 * They are built using the Merkle–Damgård construction, from a one-way compression function 
 * itself built using the Davies–Meyer structure from a specialized block cipher. (from Wikipedia)
 * 
 * @link   https://en.wikipedia.org/wiki/SHA-2
 * @link   https://datatracker.ietf.org/doc/html/rfc6234
 * @file   This file defines the sha512_256 global constant.
 * @author Korosium
 */
const sha512_256 = (() => {

    /**
     * The inner logic of the hash function.
     */
    const logic = (() => {

        /**
         * The initial registers.
         */
        const H = [0x22312194fc2bf72cn, 0x9f555fa3c84c64c2n, 0x2393b86b6f53b151n, 0x963877195940eabdn, 0x96283ee2a88effe3n, 0xbe5e1e2553863992n, 0x2b0199fc2c85b8aan, 0x0eb72ddc81c52ca2n];

        /**
         * The round constants.
         */
        const K = [0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn, 0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n, 0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n, 0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n, 0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n, 0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n, 0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n, 0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n, 0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn, 0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn, 0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n, 0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n, 0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n, 0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n, 0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn, 0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn, 0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n, 0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn, 0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn, 0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n];

        /**
         * Transform the registers by processing a slice of the data to hash.
         * 
         * @param {BigUint64Array} registers The registers to transform.
         * @param {number[]}       slice     The slice to process.
         * @param {number}         length    The total length of the data.
         * 
         * @returns {BigUint64Array} The transformed registers.
         */
        const transform = (registers, slice, length) => {
            if (slice.length === 128) return compress(registers, convert(slice));
            else if (slice.length >= 112) return compress(compress(registers, convert(pad(slice))), append(convert(pad([], 0)), length));
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
            for (let i = slice.length; i < 128; i++) slice[i] = 0;
            return slice;
        };

        /**
         * Convert the slice to a chunk.
         * 
         * @param {number[]} slice The slice to convert.
         * 
         * @returns {BigUint64Array} The new chunk.
         */
        const convert = slice => {
            let retval = new BigUint64Array(slice.length / 8);
            for (let i = 0; i < retval.length; i++) {
                const high = to_uint_32((slice[i * 8] << 24) | (slice[i * 8 + 1] << 16) | (slice[i * 8 + 2] << 8) | slice[i * 8 + 3]);
                const low = to_uint_32((slice[i * 8 + 4] << 24) | (slice[i * 8 + 5] << 16) | (slice[i * 8 + 6] << 8) | slice[i * 8 + 7]);
                retval[i] = (BigInt(high) << 32n) | BigInt(low);
            }
            return retval;
        };

        /**
         * Convert and clamp a number to a unsigned 32-bit int.
         * 
         * @param {number} n The number to convert and/or clamp.
         * 
         * @returns {number} The converted and/or clamped number.
         */
        const to_uint_32 = n => {
            if (n < 0) return n + (2 ** 32);
            return n & 0xffffffff;
        };

        /**
         * Append the total length of the data in bits at the end of the last chunk.
         * 
         * @param {BigUint64Array} chunk  The chunk to append the length to.
         * @param {number}         length The total length of the data.
         * 
         * @returns {BigUint64Array} The chunk with the total length of the data at the end.
         */
        const append = (chunk, length) => {
            const hex = (length * 8).toString(16).padStart(32, "0");
            chunk[chunk.length - 2] = BigInt(`0x${hex.substring(0, 16)}`);
            chunk[chunk.length - 1] = BigInt(`0x${hex.substring(16, 32)}`);
            return chunk;
        };

        /**
         * Compress the new chunk with the registers.
         * 
         * @param {BigUint64Array} registers The registers to compress.
         * @param {BigUint64Array} chunk     The chunk to compress.
         * 
         * @returns {BigUint64Array} The compressed registers.
         */
        const compress = (registers, chunk) => {
            const w = init(chunk);
            let r = new BigUint64Array(registers);
            for (let i = 0; i < 80; i++) {
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
         * @param {BigUint64Array} chunk The chunk to extend.
         * 
         * @returns {BigUint64Array} The extended chunk.
         */
        const init = chunk => {
            let retval = new BigUint64Array(80);
            for (let i = 0; i < 80; i++) {
                if (i < 16) retval[i] = chunk[i];
                else retval[i] = retval[i - 16] + ls0(retval[i - 15]) + retval[i - 7] + ls1(retval[i - 2]);
            }
            return retval;
        };

        /**
         * Convert the registers to a big-endian byte array.
         * 
         * @param {BigUint64Array} registers The registers to serialize.
         * 
         * @returns {number[]} The byte array checksum.
         */
        const serialize = registers => {
            let retval = [];
            for (let i = 0; i < registers.length - 4; i++) {
                retval[i * 8] = Number((registers[i] >> 56n) & 0xffn);
                retval[i * 8 + 1] = Number((registers[i] >> 48n) & 0xffn);
                retval[i * 8 + 2] = Number((registers[i] >> 40n) & 0xffn);
                retval[i * 8 + 3] = Number((registers[i] >> 32n) & 0xffn);
                retval[i * 8 + 4] = Number((registers[i] >> 24n) & 0xffn);
                retval[i * 8 + 5] = Number((registers[i] >> 16n) & 0xffn);
                retval[i * 8 + 6] = Number((registers[i] >> 8n) & 0xffn);
                retval[i * 8 + 7] = Number(registers[i] & 0xffn);
            }
            return retval;
        };

        /**
         * Rotate the bits of a number to the right by a set amount.
         * 
         * @param {bigint} n The number to rotate.
         * @param {bigint} i The amount of bits to rotate.
         * 
         * @returns {bigint} The number rotated to the right.
         */
        const rotr = (n, i) => (n >> i) | (n << (64n - i));

        /**
         * The lower sigma zero function.
         * 
         * @param {bigint} n The register to process.
         * 
         * @returns {bigint} The modified register.
         */
        const ls0 = n => rotr(n, 1n) ^ rotr(n, 8n) ^ (n >> 7n);

        /**
         * The lower sigma one function.
         * 
         * @param {bigint} n The register to process.
         * 
         * @returns {bigint} The modified register.
         */
        const ls1 = n => rotr(n, 19n) ^ rotr(n, 61n) ^ (n >> 6n);

        /**
         * The upper sigma zero function.
         * 
         * @param {bigint} n The register to process.
         * 
         * @returns {bigint} The modified register.
         */
        const us0 = n => rotr(n, 28n) ^ rotr(n, 34n) ^ rotr(n, 39n);

        /**
         * The upper sigma one function.
         * 
         * @param {bigint} n The register to process.
         * 
         * @returns {bigint} The modified register.
         */
        const us1 = n => rotr(n, 14n) ^ rotr(n, 18n) ^ rotr(n, 41n);

        /**
         * The choice function.
         * 
         * @param {bigint} x The first number.
         * @param {bigint} y The second number.
         * @param {bigint} z The third number.
         * 
         * @returns The new number.
         */
        const ch = (x, y, z) => (x & y) ^ ((~x) & z);

        /**
         * The majority function.
         * 
         * @param {bigint} x The first number.
         * @param {bigint} y The second number.
         * @param {bigint} z The third number.
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
            process(data) {
                const bytes = conversion.to_byte(data);
                let registers = new BigUint64Array(H);
                for (let i = 0; i <= bytes.length; i += 128) registers = transform(registers, bytes.slice(i, i + 128), bytes.length);
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