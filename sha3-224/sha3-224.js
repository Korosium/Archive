"use strict";
/**
 * JavaScript implementation of the SHA3-224 algorithm.
 * 
 * SHA-3 (Secure Hash Algorithm 3) is the latest member of the Secure Hash Algorithm family of standards, 
 * released by NIST on August 5, 2015. Although part of the same series of standards, 
 * SHA-3 is internally different from the MD5-like structure of SHA-1 and SHA-2. 
 * 
 * @link   https://en.wikipedia.org/wiki/SHA-3
 * @link   https://keccak.team/keccak.html
 * @file   This file defines the sha3_224 global constant.
 * @author Korosium
 */
const sha3_224 = (() => {

    /**
     * The rate of the hash function.
     */
    const R = 144;

    /**
     * The checksum length.
     */
    const CHECKSUM_LENGTH = 28;

    /**
     * The Keccak function used to hash the data.
     */
    const keccak = (() => {

        /**
         * The first padding byte to add to the last chunk.
         */
        const BEGINNING_PAD = 0x06;

        /**
         * The last padding byte to add to the last chunk.
         */
        const ENDING_PAD = 0x80;

        /**
         * The amount of rounds the Keccak-f sub-function will execute.
         */
        const ROUNDS = 24;

        /**
         * The round constants used by the Iota sub-function.
         */
        const RC = [0x8000000000000000n, 0x4101000000000000n, 0x5101000000000001n, 0x0001000100000001n, 0xd101000000000000n, 0x8000000100000000n, 0x8101000100000001n, 0x9001000000000001n, 0x5100000000000000n, 0x1100000000000000n, 0x9001000100000000n, 0x5000000100000000n, 0xd101000100000000n, 0xd100000000000001n, 0x9101000000000001n, 0xc001000000000001n, 0x4001000000000001n, 0x0100000000000001n, 0x5001000000000000n, 0x5000000100000001n, 0x8101000100000001n, 0x0101000000000001n, 0x8000000100000000n, 0x1001000100000001n];

        /**
         * The rotation offsets used by the Rho and Pi sub-functions.
         */
        const ROTATION_OFFSETS = [0n, 36n, 3n, 41n, 18n, 1n, 44n, 10n, 45n, 2n, 62n, 6n, 43n, 15n, 61n, 28n, 55n, 25n, 21n, 56n, 27n, 20n, 39n, 8n, 14n];

        /**
         * The number of lane in the state.
         */
        const STATE_SIZE = 25;

        /**
         * The number of lane in a row.
         */
        const ROW_SIZE = 5;

        /**
         * Perform a set amount of operations on the state.
         * 
         * @param {BigUint64Array} state The state to execute Keccak-f on it.
         * 
         * @returns {BigUint64Array} The altered state.
         */
        const keccak_f = state => {
            for (let i = 0; i < ROUNDS; i++) {
                state = round(state, RC[i]);
            }
            return state;
        };

        /**
         * Perform the Theta, Rho, Pi, Chi and Iota sub-function sequentially.
         * 
         * @param {BigUint64Array} state The state to alter.
         * @param {bigint}         rc    The round constant for the Iota sub-function.
         * 
         * @returns {BigUint64Array} The altered state.
         */
        const round = (state, rc) => {
            state = theta(state);
            state = chi(state, rho_and_pi(state));
            state = iota(state, rc);
            return state;
        };

        /**
         * Perform the Theta logic on the state.
         * 
         * @param {BigUint64Array} state The state to alter.
         * 
         * @returns {BigUint64Array} The altered state.
         */
        const theta = state => {
            let c = new BigUint64Array(ROW_SIZE);
            for (let i = 0; i < ROW_SIZE; i++) c[i] = state[i * ROW_SIZE] ^ state[i * ROW_SIZE + 1] ^ state[i * ROW_SIZE + 2] ^ state[i * ROW_SIZE + 3] ^ state[i * ROW_SIZE + 4];
            let d = new BigUint64Array(ROW_SIZE);
            for (let i = 0; i < ROW_SIZE; i++) d[i] = c[(i - 1 + ROW_SIZE) % ROW_SIZE] ^ rotr(c[(i + 1) % ROW_SIZE], 1n);
            for (let i = 0; i < STATE_SIZE; i++) state[i] ^= d[(i / ROW_SIZE) & 0xff];
            return state;
        };

        /**
         * Perform the Rho and Pi logics on the state.
         * 
         * @param {BigUint64Array} state The state to alter.
         * 
         * @returns {BigUint64Array} The temporary state.
         */
        const rho_and_pi = state => {
            let temp_state = new BigUint64Array(STATE_SIZE);
            for (let i = 0; i < STATE_SIZE; i++) {
                const row = (i / ROW_SIZE & 0xff);
                const first = row * ROW_SIZE + (2 * (i % ROW_SIZE) + 3 * row) % ROW_SIZE;
                const second = (i * ROW_SIZE) % STATE_SIZE + row;
                temp_state[first] = rotr(state[second], ROTATION_OFFSETS[second]);
            }
            return temp_state;
        };

        /**
         * Perform the Chi logic on the state.
         * 
         * @param {BigUint64Array} state      The state to alter.
         * @param {BigUint64Array} temp_state The temporary state from the Rho and Pi sub-function.
         * 
         * @returns {BigUint64Array} The altered state.
         */
        const chi = (state, temp_state) => {
            for (let i = 0; i < STATE_SIZE; i++) {
                const row = i / ROW_SIZE & 0xff;
                const first = i * ROW_SIZE % STATE_SIZE + row;
                const second = (i + 1) * ROW_SIZE % STATE_SIZE + row;
                const third = (i + 2) * ROW_SIZE % STATE_SIZE + row;
                state[first] = temp_state[first] ^ ~temp_state[second] & temp_state[third];
            }
            return state;
        };

        /**
         * Perform the Iota logic on the state.
         * 
         * @param {BigUint64Array} state The state to alter.
         * @param {bigint}         rc    The round constant.
         * 
         * @returns {BigUint64Array} The altered state.
         */
        const iota = (state, rc) => {
            state[0] ^= rc;
            return state;
        };

        /**
         * Pad and reverse the bits of the chunk.
         * 
         * @param {number[]} chunk The chunk to initialize.
         * @param {number}   rate  The length of the initialized chunk.
         * 
         * @returns {number[]} The initialized chunk.
         */
        const init_chunk = (chunk, rate) => {
            if (chunk.length === rate) return reverse_byte_array(chunk);

            const missing_bytes = rate - chunk.length;
            if (missing_bytes === 1) {
                chunk.push(BEGINNING_PAD + ENDING_PAD);
                return reverse_byte_array(chunk);
            }
            
            chunk.push(BEGINNING_PAD);
            for (let i = 0; i < missing_bytes - 2; i++) {
                chunk.push(0);
            }
            chunk.push(ENDING_PAD);
            return reverse_byte_array(chunk);
        };

        /**
         * Reverse all the bits in a byte. The first bit goes to the last position and so on.
         * 
         * @param {number} n The byte to reverse the bits.
         * 
         * @returns {number} The reversed byte.
         */
        const reverse_byte = n => ((n & 0b10000000) >>> 7) | ((n & 0b01000000) >>> 5) | ((n & 0b00100000) >>> 3) | ((n & 0b00010000) >>> 1) | ((n & 0b00001000) << 1) | ((n & 0b00000100) << 3) | ((n & 0b00000010) << 5) | ((n & 0b00000001) << 7);

        /**
         * Reverse all the bits of all the bytes in an array.
         * 
         * @param {number[]} arr The byte array to reverse the bits from.
         * 
         * @returns {number[]} The reversed byte array.
         */
        const reverse_byte_array = arr => arr.map(x => reverse_byte(x));

        /**
         * Perform an exclusive or operation by adding the chunk to the state array.
         * 
         * @param {BigUint64Array} state The state array that will receive the chunk.
         * @param {number[]}       chunk The initialized chunk to XOR with the state array.
         * @param {number}         rate  The length of the initialized chunk.
         * 
         * @returns {BigUint64Array} The altered state.
         */
        const xor_state = (state, chunk, rate) => {
            for (let i = 0; i < rate; i += 8) {
                state[i / 8 * ROW_SIZE % STATE_SIZE + i / 8 / ROW_SIZE & 0xff] ^= byte_to_uint64(chunk.slice(i, i + 8));
            }
            return state;
        };

        /**
         * Extract the working bytes from the state array.
         * 
         * @param {BigUint64Array} state The state to extract the bytes from.
         * @param {number}         rate  The length of the accessible bytes in the state.
         * 
         * @returns {number[]} The extracted byte array.
         */
        const extract_byte = (state, rate) => {
            let output = [];
            for (let i = 0; i < STATE_SIZE; i++) {
                output = output.concat(reverse_byte_array(uint64_to_byte(state[i * ROW_SIZE % STATE_SIZE + i / ROW_SIZE & 0xff])));
                if (output.length >= rate) break;
            }
            return output.slice(0, rate);
        };

        /**
         * Convert an unsigned 64 bit big int to a 8 bytes array.
         * 
         * @param {bigint} n The unsigned 64 bit big int to convert.
         * 
         * @returns {number[]} The byte array.
         */
        const uint64_to_byte = n => [Number(n >> 56n), Number(n >> 48n & 0xffn), Number(n >> 40n & 0xffn), Number(n >> 32n & 0xffn), Number(n >> 24n & 0xffn), Number(n >> 16n & 0xffn), Number(n >> 8n & 0xffn), Number(n & 0xffn)];

        /**
         * Convert a 8 bytes array to a unsigned 64 bit big int.
         * 
         * @param {number[]} b The byte array to convert.
         * 
         * @returns {bigint} The unsigned 64 bit big int.
         */
        const byte_to_uint64 = b => ((BigInt(b[0]) << 56n) | (BigInt(b[1]) << 48n) | (BigInt(b[2]) << 40n) | (BigInt(b[3]) << 32n) | (BigInt(b[4]) << 24n) | (BigInt(b[5]) << 16n) | (BigInt(b[6]) << 8n) | BigInt(b[7]));

        /**
         * Rotate a unsigned 64 bit big int to the right.
         * 
         * @param {bigint} n The unsigned 64 bit big int to rotate.
         * @param {bigint} i The number of bits to rotate.
         * 
         * @returns {bigint} The rotated unsigned 64 bit big int.
         */
        const rotr = (n, i) => (n >> i) | (n << (64n - i));

        return {

            /**
             * Perform the Keccak logic on some data.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data   The data to perform the Keccak operation on.
             * @param {number}                                       rate   The maximum possible length of a chunk in bytes.
             * @param {number}                                       length The length of the garbled data.
             * 
             * @returns {number[]} The garbled data.
             */
            keccak(data, rate, length) {
                const bytes = conversion.to_byte(data);

                // Absorbing phase
                let state = new BigUint64Array(STATE_SIZE);
                for (let i = 0; i <= bytes.length; i += rate) {
                    state = keccak_f(xor_state(state, init_chunk(bytes.slice(i, i + rate), rate), rate));
                }
                
                // Squeezing phase
                let output = extract_byte(state, rate);
                while (output.length < length) {
                    state = keccak_f(state);
                    output = output.concat(extract_byte(state, rate));
                }
                return output.slice(0, length);
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
                return keccak.keccak(data, R, CHECKSUM_LENGTH);
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