"use strict";
/**
 * JavaScript implementation of the Advanced Encryption Standard algorithm.
 * 
 * AES is a variant of the Rijndael block cipher developed by two Belgian cryptographers, 
 * Joan Daemen and Vincent Rijmen, who submitted a proposal to NIST during the AES selection process.
 * Rijndael is a family of ciphers with different key and block sizes. 
 * For AES, NIST selected three members of the Rijndael family, each with a block size of 128 bits, 
 * but three different key lengths: 128, 192 and 256 bits. (from Wikipedia)
 * 
 * @link   https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * @link   https://csrc.nist.gov/pubs/fips/197/final
 * @file   This file defines the aes global constant.
 * @author Korosium
 */
const aes = (() => {

    /**
     * The length of the state in bytes.
     */
    const STATE_SIZE = 16;

    /**
     * The length of the nonce in bytes for the CTR mode.
     */
    const COUNTER_MODE_NONCE_LENGTH = 12;

    /**
     * The primitve used to process the data.
     */
    const rijndael = (() => {

        /**
         * The substitution box for encryption.
         */
        const SBOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
        
        /**
         * The inverse substitution box for decryption.
         */
        const I_SBOX = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];

        /**
         * The key expansion algorithm for both processes.
         */
        const key_expansion = (() => {

            /**
             * The round constants.
             */
            const RCON = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000];

            /**
             * Rotate a number to the left by a byte.
             * 
             * @param {number} n The number to rotate.
             * 
             * @returns {number} The rotated number.
             */
            const rot_word = n => (n << 8) | (n >>> 24);
            
            /**
             * Substitute the 4 bytes number with the S-Box.
             * 
             * @param {number} n The number to substitute.
             * 
             * @returns {number} The substituted number.
             */
            const sub_word = n => (SBOX[n >>> 24 & 0xff] << 24) | (SBOX[n >>> 16 & 0xff] << 16) | (SBOX[n >>> 8 & 0xff] << 8) | SBOX[n & 0xff];

            /**
             * Convert the expanded key to a byte array.
             * 
             * @param {Uint32Array} w The expanded key to convert.
             * 
             * @returns {number[]} The byte array key.
             */
            const serialize = w => {
                let retval = [];
                for (let i = 0; i < w.length; i++) {
                    retval[i * 4] = (w[i] >>> 24) & 0xff;
                    retval[i * 4 + 1] = (w[i] >>> 16) & 0xff;
                    retval[i * 4 + 2] = (w[i] >>> 8) & 0xff;
                    retval[i * 4 + 3] = w[i] & 0xff;
                }
                return retval;
            };

            return {

                /**
                 * Expand the original key using the S-Box.
                 * 
                 * @param {number[]} key The original key to convert.
                 * @param {number}   k   The number of initial words.
                 * @param {number}   r   The number of rounds.
                 * 
                 * @returns {number[]} The expanded key byte array.
                 */
                process(key, k, r) {
                    let w = new Uint32Array(4 * (r + 1));
                    for (let i = 0; i < k; i++) w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
                    for (let i = k; i < w.length; i++) {
                        let temp = w[i - 1];
                        if (i % k === 0) temp = sub_word(rot_word(temp)) ^ RCON[i / k - 1];
                        else if (k > 6 && i % k === 4) temp = sub_word(temp);
                        w[i] = w[i - k] ^ temp;
                    }
                    return serialize(w);
                }

            }

        })();

        /**
         * The Rijndael logic.
         */
        const logic = (() => {

            /**
             * The first lookup table for the Galois-Field.
             */
            const L_TABLE = [0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03, 0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1, 0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78, 0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e, 0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38, 0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10, 0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba, 0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57, 0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8, 0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0, 0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7, 0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d, 0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1, 0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab, 0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5, 0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07];
            
            /**
             * The second lookup table for the Galois-Field.
             */
            const E_TABLE = [0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35, 0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa, 0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31, 0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd, 0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88, 0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a, 0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3, 0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0, 0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41, 0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75, 0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80, 0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54, 0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca, 0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e, 0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17, 0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01];

            /**
             * Execute a multiplication of two polynomials in a Galois-Field.
             * 
             * @param {number} a The first polynomial to multiply.
             * @param {number} b The second polynomial to multiply.
             * 
             * @returns {number} The product of the multiplication.
             */
            const time_x = (a, b) => {
                if (a === 0 || b === 0) return 0;
                let n = L_TABLE[a] + L_TABLE[b];
                if (n > 0xff) n -= 0xff;
                return E_TABLE[n];
            };

            /**
             * Perform a matrix multiplication on one column of the state.
             * 
             * @param {number[]} state  The current state.
             * @param {number[]} matrix The multiplication matrix.
             * @param {number}   i      The current column of the state.
             * @param {number}   j      The current column of the matrix.
             * 
             * @returns The resulting matrix multiplication of one column.
             */
            const add_x = (state, matrix, i, j) => time_x(state[i], matrix[j * 4]) ^ time_x(state[i + 1], matrix[j * 4 + 1]) ^ time_x(state[i + 2], matrix[j * 4 + 2]) ^ time_x(state[i + 3], matrix[j * 4 + 3]);

            return {

                /**
                 * Substitute the bytes of the state with the appropriate S-Box.
                 * 
                 * @param {number[]} state The current state.
                 * @param {number[]} box   The chosen S-Box.
                 * 
                 * @returns {number[]} The substituted state.
                 */
                sub_bytes(state, box) {
                    return state.map(x => box[x]);
                },

                /**
                 * Shift all the rows of the state with the appropriate indexes.
                 * 
                 * @param {number[]}                state   The current state.
                 * @param {[{x: number, y:number}]} indexes The chosen indexes.
                 * 
                 * @returns {number[]} The shifted state.
                 */
                shift_rows(state, indexes) {
                    for (let i = 0; i < indexes.length; i++) {
                        let temp = state[indexes[i].x];
                        state[indexes[i].x] = state[indexes[i].y];
                        state[indexes[i].y] = temp;
                    }
                    return state;
                },

                /**
                 * Perform a matrix multiplication on the whole state with the appropriate multiplication matrix.
                 * 
                 * @param {number[]} state  The current state.
                 * @param {number[]} matrix The chosen multiplication matrix.
                 * 
                 * @returns The multiplicated state.
                 */
                mix_columns(state, matrix) {
                    for (let i = 0; i < state.length; i += 4) {
                        const products = [0, 0, 0, 0].map((x, j) => x + add_x(state, matrix, i, j));
                        for (let j = 0; j < products.length; j++) state[i + j] = products[j];
                    }
                    return state;
                },

                /**
                 * XOR a part of the expanded key.
                 * 
                 * @param {number[]} state The current state.
                 * @param {number[]} key   The current chunk of the key to XOR to the state.
                 * 
                 * @returns {number[]} The XORed state.
                 */
                add_round_key(state, key) {
                    return state.map((x, i) => x ^ key[i]);
                }

            }

        })();

        /**
         * The encryption logic.
         */
        const cipher = (() => {

            /**
             * The indexes used for the shift rows step.
             */
            const SHIFT_ROWS_INDEXES = [{ x: 1, y: 5 }, { x: 5, y: 9 }, { x: 9, y: 13 }, { x: 2, y: 10 }, { x: 6, y: 14 }, { x: 15, y: 11 }, { x: 11, y: 7 }, { x: 7, y: 3 }];
            
            /**
             * The multiplication matrix for the mix columns step.
             */
            const MATRIX = [0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x03, 0x01, 0x01, 0x02];

            /**
             * Substitute the bytes of the state with the S-Box.
             * 
             * @param {number[]} state The current state.
             * 
             * @returns {number[]} The substituted state.
             */
            const sub_bytes = state => logic.sub_bytes(state, SBOX);

            /**
             * Shift all the rows of the state.
             * 
             * @param {number[]} state The current state.
             * 
             * @returns {number[]} The shifted state.
             */
            const shift_rows = state => logic.shift_rows(state, SHIFT_ROWS_INDEXES);

            /**
             * Multiply the state with the multiplication matrix.
             * 
             * @param {number[]} state The current state.
             * 
             * @returns {number[]} The multiplicated state.
             */
            const mix_columns = state => logic.mix_columns(state, MATRIX);

            return {

                /**
                 * Encrypt a 16 bytes long byte array with a byte array key.
                 * 
                 * @param {number[]} chunk The 16 bytes chunk to encrypt.
                 * @param {number[]} key   The 16, 24 or 32 bytes key.
                 * @param {number}   r     The number or rounds the algorithm will perform.
                 * 
                 * @returns {number[]} The encrypted byte array.
                 */
                process(chunk, key, r) {
                    let state = logic.add_round_key(chunk, key.slice(0, STATE_SIZE));
                    for (let i = 1; i < r; i++) state = logic.add_round_key(mix_columns(shift_rows(sub_bytes(state))), key.slice(i * STATE_SIZE, i * STATE_SIZE + STATE_SIZE));
                    return logic.add_round_key(shift_rows(sub_bytes(state)), key.slice(r * STATE_SIZE, r * STATE_SIZE + STATE_SIZE));
                }

            }

        })();

        /**
         * The decryption logic.
         */
        const inv_cipher = (() => {

            /**
             * The indexes used for the shift rows step.
             */
            const INV_SHIFT_ROWS_INDEXES = [{ x: 9, y: 13 }, { x: 5, y: 9 }, { x: 1, y: 5 }, { x: 2, y: 10 }, { x: 6, y: 14 }, { x: 7, y: 3 }, { x: 11, y: 7 }, { x: 15, y: 11 }];
            
            /**
             * The multiplication matrix for the mix columns step.
             */
            const I_MATRIX = [0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d, 0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e];

            /**
             * Substitute the bytes of the state with the inverse S-Box.
             * 
             * @param {number[]} state The current state.
             * 
             * @returns {number[]} The substituted state.
             */
            const inv_sub_bytes = state => logic.sub_bytes(state, I_SBOX);

            /**
             * Shift all the rows of the state.
             * 
             * @param {number[]} state The current state.
             * 
             * @returns {number[]} The shifted state.
             */
            const inv_shift_rows = state => logic.shift_rows(state, INV_SHIFT_ROWS_INDEXES);

            /**
             * Multiply the state with the inverse multiplication matrix.
             * 
             * @param {number[]} state The current state.
             * 
             * @returns {number[]} The multiplicated state.
             */
            const inv_mix_columns = state => logic.mix_columns(state, I_MATRIX);

            return {

                /**
                 * Decrypt a 16 bytes long byte array with a byte array key.
                 * 
                 * @param {number[]} chunk The 16 bytes chunk to decrypt.
                 * @param {number[]} key   The 16, 24 or 32 bytes key.
                 * @param {number}   r     The number or rounds the algorithm will perform.
                 * 
                 * @returns {number[]} The decrypted byte array.
                 */
                process(chunk, key, r) {
                    let state = logic.add_round_key(chunk, key.slice(r * STATE_SIZE, r * STATE_SIZE + STATE_SIZE));
                    for (let i = r - 1; i > 0; i--) state = inv_mix_columns(logic.add_round_key(inv_sub_bytes(inv_shift_rows(state)), key.slice(i * STATE_SIZE, i * STATE_SIZE + STATE_SIZE)));
                    return logic.add_round_key(inv_sub_bytes(inv_shift_rows(state)), key.slice(0, STATE_SIZE));
                }

            }

        })();

        return {

            /**
             * Expand the original key using the S-Box.
             * 
             * @param {number[]} key The original key to convert.
             * @param {number}   k   The number of initial words.
             * @param {number}   r   The number of rounds.
             * 
             * @returns {number[]} The expanded key byte array.
             */
            expand_key(key, k, r) {
                return key_expansion.process(key, k, r);
            },

            /**
             * Encrypt a 16 bytes long byte array with a byte array key.
             * 
             * @param {number[]} chunk The 16 bytes chunk to encrypt.
             * @param {number[]} key   The 16, 24 or 32 bytes key.
             * @param {number}   r     The number or rounds the algorithm will perform.
             * 
             * @returns {number[]} The encrypted byte array.
             */
            cipher(chunk, key, r) {
                return cipher.process(chunk, key, r);
            },

            /**
             * Decrypt a 16 bytes long byte array with a byte array key.
             * 
             * @param {number[]} chunk The 16 bytes chunk to decrypt.
             * @param {number[]} key   The 16, 24 or 32 bytes key.
             * @param {number}   r     The number or rounds the algorithm will perform.
             * 
             * @returns {number[]} The decrypted byte array.
             */
            inv_cipher(chunk, key, r) {
                return inv_cipher.process(chunk, key, r);
            }

        }

    })();

    /**
     * Helper functions to convert the parameters.
     */
    const parameters = (() => {

        /**
         * The number of initial words for 128, 192 and 256 bit keys respectively.
         */
        const K = [4, 6, 8];

        /**
         * The number of rounds for 128, 192 and 256 bit keys respectively.
         */
        const R = [10, 12, 14];

        /**
         * Pad a byte array up to a desired length.
         * 
         * @param {number[]} bytes  The byte array to pad.
         * @param {number}   length The desired length of the byte array.
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
         * Pad the key so it falls between 128, 192 and 256 bits length.
         * 
         * @param {number[]} key The key to pad.
         * 
         * @returns {number[]} The padded key.
         */
        const pad_key = key => {
            if (key.length === 16 || key.length === 24 || key.length === 32) return key;
            if (key.length < 16) return pad_bytes(key, 16, 0);
            if (key.length < 24) return pad_bytes(key, 24, 0);
            if (key.length < 32) return pad_bytes(key, 32, 0);
            return key.slice(0, 32);
        };

        /**
         * Pad the initialization vector for it to be of the length of the state.
         * 
         * @param {number[]} iv The initialization vector to pad.
         * 
         * @returns {number[]} The padded initialization vector.
         */
        const pad_iv = iv => {
            if (iv.length === STATE_SIZE) return iv;
            if (iv.length < STATE_SIZE) return pad_bytes(iv, STATE_SIZE, 0);
            return iv.slice(0, STATE_SIZE);
        };

        /**
         * Pad the plaintext data for it to be a multiple of the length of the state.
         * 
         * @param {number[]} data The plaintext byte array to pad.
         * @param {boolean}  pad  If the plaintext has to be padded or not.
         * 
         * @returns {number[]} The padded byte array.
         */
        const pad_data = (data, pad) => {
            if (!pad) return data;
            const to_pad = STATE_SIZE - (data.length % STATE_SIZE);
            return pad_bytes(data, data.length + to_pad, to_pad);
        };

        /**
         * Choose the right K and R combination based on the key length.
         * 
         * @param {number[]} key The key to get the K and R from.
         * 
         * @returns {{k: number; r: number;}} The K and R combination.
         */
        const choose_combination = key => {
            switch (key.length) {
                case 16: return { k: K[0], r: R[0] };
                case 24: return { k: K[1], r: R[1] };
                case 32: return { k: K[2], r: R[2] };
            }
        };

        return {

            /**
             * Format the parameters for them to be of right length and conform to the AES algorithm.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} key     The key used for the encryption or decryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer} iv      The initialization vector used for the encryption or decryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer} data    The data used for the encryption or decryption process.
             * @param {boolean}                                      padding If the plaintext must be padded or not.
             * 
             * @returns {{key: number[]; iv: number[]; data: number[]; r: number;}} The formated parameters.
             */
            get_parameters(key, iv, data, padding) {
                const key_bytes = pad_key(conversion.to_byte(key));
                const iv_bytes = pad_iv(conversion.to_byte(iv));
                const data_bytes = pad_data(conversion.to_byte(data), padding);
                const combination = choose_combination(key_bytes);
                const expanded_key = rijndael.expand_key(key_bytes, combination.k, combination.r);
                return {
                    key: expanded_key,
                    iv: iv_bytes,
                    data: data_bytes,
                    r: combination.r
                }
            },

            /**
             * Format the parameters for them to be of right length and conform to the AES-CTR algorithm.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} key   The key used for the encryption or decryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer} nonce The nonce used for the encryption or decryption process.
             * @param {number[] | string | Uint8Array | ArrayBuffer} data  The data used for the encryption or decryption process.
             * 
             * @returns {{key: number[]; nonce: number[]; data: number[]; r: number;}} The formated CTR parameters.
             */
            get_parameters_CTR(key, nonce, data) {
                const params = this.get_parameters(key, nonce, data, false);
                return {
                    key: params.key,
                    nonce: params.iv.slice(0, COUNTER_MODE_NONCE_LENGTH),
                    data: params.data,
                    r: params.r
                }
            }

        }

    })();

    /**
     * The electronic codebook mode of operation.
     */
    const ecb = (() => {

        /**
         * The ECB logic.
         */
        const logic = (() => {

            return {

                /**
                 * Encrypt some data with the ECB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key       The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext The plaintext to encrypt.
                 * @param {boolean}                                      padding   If the plaintext must be padded or not.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                encrypt(key, plaintext, padding) {
                    const params = parameters.get_parameters(key, [], plaintext, padding);
                    let ciphertext = [];
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        rijndael.cipher(params.data.slice(i, i + STATE_SIZE), params.key, params.r).map(x => ciphertext.push(x));
                    }
                    return ciphertext;
                },

                /**
                 * Decrypt some data with the ECB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} ciphertext The ciphertext to decrypt.
                 * @param {boolean}                                      padding    If the plaintext was padded or not.
                 * 
                 * @returns {number[]} The plaintext byte array.
                 */
                decrypt(key, ciphertext, padding) {
                    const params = parameters.get_parameters(key, [], ciphertext, false);
                    let plaintext = [];
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        rijndael.inv_cipher(params.data.slice(i, i + STATE_SIZE), params.key, params.r).map(x => plaintext.push(x));
                    }
                    return padding ? plaintext.slice(0, plaintext.length - plaintext[plaintext.length - 1]) : plaintext;
                }

            }

        })();

        /**
         * The available encryption encodings.
         */
        const encrypt = (() => {

            return {

                /**
                 * Encrypt some data with the ECB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext        The plaintext to encrypt.
                 * @param {boolean | undefined}                          [padding = true] If the plaintext must be padded or not. Default is true.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                array(key, plaintext, padding = true) {
                    return logic.encrypt(key, plaintext, padding);
                },

                /**
                 * Encrypt some data with the ECB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext        The plaintext to encrypt.
                 * @param {boolean | undefined}                          [padding = true] If the plaintext must be padded or not. Default is true.
                 * 
                 * @returns {string} The ciphertext hex string.
                 */
                hex(key, plaintext, padding = true) {
                    return conversion.to_hex(this.array(key, plaintext, padding));
                },

                /**
                 * Encrypt some data with the ECB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext        The plaintext to encrypt.
                 * @param {boolean | undefined}                          [padding = true] If the plaintext must be padded or not. Default is true.
                 * 
                 * @returns {string} The ciphertext Base64 string.
                 */
                base64(key, plaintext, padding = true) {
                    return conversion.to_base64(this.array(key, plaintext, padding));
                }

            }

        })();

        /**
         * The available decryption encodings.
         */
        const decrypt = (() => {

            /**
             * Decrypts a byte array to other encodings.
             */
            const array = (() => {

                return {

                    /**
                     * Decrypt a ciphertext byte array with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {number[]}                                     ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, padding = true) {
                        return logic.decrypt(key, ciphertext, padding);
                    },

                    /**
                     * Decrypt a ciphertext byte array with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {number[]}                                     ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, padding = true) {
                        return conversion.to_hex(this.to_array(key, ciphertext, padding));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {number[]}                                     ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, padding = true) {
                        return conversion.to_base64(this.to_array(key, ciphertext, padding));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {number[]}                                     ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, padding = true) {
                        return conversion.to_utf8(this.to_array(key, ciphertext, padding));
                    }

                }

            })();

            /**
             * Decrypts a hex string to other encodings.
             */
            const hex = (() => {

                return {

                    /**
                     * Decrypt a ciphertext hex string with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, padding = true) {
                        return logic.decrypt(key, conversion.from_hex(ciphertext), padding);
                    },

                    /**
                     * Decrypt a ciphertext hex string with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, padding = true) {
                        return conversion.to_hex(this.to_array(key, ciphertext), padding);
                    },

                    /**
                     * Decrypt a ciphertext hex string with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, padding = true) {
                        return conversion.to_base64(this.to_array(key, ciphertext), padding);
                    },

                    /**
                     * Decrypt a ciphertext hex string with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, padding = true) {
                        return conversion.to_utf8(this.to_array(key, ciphertext), padding);
                    }

                }

            })();

            /**
             * Decrypts a Base64 string to other encodings.
             */
            const base64 = (() => {

                return {

                    /**
                     * Decrypt a ciphertext Base64 string with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, padding = true) {
                        return logic.decrypt(key, conversion.from_base64(ciphertext), padding);
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, padding = true) {
                        return conversion.to_hex(this.to_array(key, ciphertext), padding);
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, padding = true) {
                        return conversion.to_base64(this.to_array(key, ciphertext), padding);
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the ECB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, padding = true) {
                        return conversion.to_utf8(this.to_array(key, ciphertext), padding);
                    }

                }

            })();

            return {

                array: array,
                hex: hex,
                base64: base64

            }

        })();

        return {

            encrypt: encrypt,
            decrypt: decrypt

        }

    })();

    /**
     * The cipher block chaining mode of operation.
     */
    const cbc = (() => {

        /**
         * The CBC logic.
         */
        const logic = (() => {

            return {

                /**
                 * Encrypt some data with the CBC mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key       The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} iv        The initialization vector used for the encryption process.
                 * @param {boolean}                                      padding   If the plaintext must be padded or not.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                encrypt(key, plaintext, iv, padding) {
                    const params = parameters.get_parameters(key, iv, plaintext, padding);
                    let ciphertext = params.iv.slice();
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        rijndael.cipher(params.data.slice(i, i + STATE_SIZE).map((x, j) => x ^ ciphertext[i + j]), params.key, params.r).map(x => ciphertext.push(x));
                    }
                    return ciphertext;
                },

                /**
                 * Decrypt some data with the CBC mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} ciphertext The ciphertext to decrypt.
                 * @param {boolean}                                      padding    If the plaintext was padded or not.
                 * 
                 * @returns {number[]} The plaintext byte array.
                 */
                decrypt(key, ciphertext, padding) {
                    const params = parameters.get_parameters(key, ciphertext.slice(0, STATE_SIZE), ciphertext.slice(STATE_SIZE), false);
                    let plaintext = [];
                    let current_iv = params.iv.slice();
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        rijndael.inv_cipher(params.data.slice(i, i + STATE_SIZE), params.key, params.r).map((x, j) => plaintext.push(x ^ current_iv[j]));
                        current_iv = params.data.slice(i, i + STATE_SIZE);
                    }
                    return padding ? plaintext.slice(0, plaintext.length - plaintext[plaintext.length - 1]) : plaintext;
                }

            }

        })();

        /**
         * The available encryption encodings.
         */
        const encrypt = (() => {

            return {

                /**
                 * Encrypt some data with the CBC mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext        The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]]  The initialization vector used for the encryption process. A random IV is generated by default.
                 * @param {boolean | undefined}                                      [padding = true] If the plaintext must be padded or not. Default is true.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                array(key, plaintext, iv = utility.generate_CBC_CFB_IV(), padding = true) {
                    return logic.encrypt(key, plaintext, iv, padding);
                },

                /**
                 * Encrypt some data with the CBC mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext        The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]]  The initialization vector used for the encryption process. A random IV is generated by default.
                 * @param {boolean | undefined}                                      [padding = true] If the plaintext must be padded or not. Default is true.
                 * 
                 * @returns {string} The ciphertext hex string.
                 */
                hex(key, plaintext, iv = utility.generate_CBC_CFB_IV(), padding = true) {
                    return conversion.to_hex(this.array(key, plaintext, iv, padding));
                },

                /**
                 * Encrypt some data with the CBC mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key              The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext        The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]]  The initialization vector used for the encryption process. A random IV is generated by default.
                 * @param {boolean | undefined}                                      [padding = true] If the plaintext must be padded or not. Default is true.
                 * 
                 * @returns {string} The ciphertext Base64 string.
                 */
                base64(key, plaintext, iv = utility.generate_CBC_CFB_IV(), padding = true) {
                    return conversion.to_base64(this.array(key, plaintext, iv, padding));
                }

            }

        })();

        /**
         * The available decryption encodings.
         */
        const decrypt = (() => {

            /**
             * Decrypts a byte array to other encodings.
             */
            const array = (() => {

                return {

                    /**
                     * Decrypt a ciphertext byte array with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {number[]}                                     ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, padding = true) {
                        return logic.decrypt(key, ciphertext, padding);
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {number[]}                                     ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, padding = true) {
                        return conversion.to_hex(this.to_array(key, ciphertext, padding));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {number[]}                                     ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, padding = true) {
                        return conversion.to_base64(this.to_array(key, ciphertext, padding));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {number[]}                                     ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, padding = true) {
                        return conversion.to_utf8(this.to_array(key, ciphertext, padding));
                    }

                }

            })();

            /**
             * Decrypts a hex string to other encodings.
             */
            const hex = (() => {

                return {

                    /**
                     * Decrypt a ciphertext hex string with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, padding = true) {
                        return logic.decrypt(key, conversion.from_hex(ciphertext), padding);
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, padding = true) {
                        return conversion.to_hex(this.to_array(key, ciphertext, padding));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, padding = true) {
                        return conversion.to_base64(this.to_array(key, ciphertext, padding));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, padding = true) {
                        return conversion.to_utf8(this.to_array(key, ciphertext, padding));
                    }

                }

            })();

            /**
             * Decrypts a Base64 string to other encodings.
             */
            const base64 = (() => {

                return {

                    /**
                     * Decrypt a ciphertext Base64 string with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, padding = true) {
                        return logic.decrypt(key, conversion.from_base64(ciphertext), padding);
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, padding = true) {
                        return conversion.to_hex(this.to_array(key, ciphertext, padding));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, padding = true) {
                        return conversion.to_base64(this.to_array(key, ciphertext, padding));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CBC mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key              The key used for the decryption process.
                     * @param {string}                                       ciphertext       The ciphertext to decrypt.
                     * @param {boolean | undefined}                          [padding = true] If the plaintext was padded or not. Default is true.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, padding = true) {
                        return conversion.to_utf8(this.to_array(key, ciphertext, padding));
                    }

                }

            })();

            return {

                array: array,
                hex: hex,
                base64: base64

            }

        })();

        return {

            encrypt: encrypt,
            decrypt: decrypt

        }

    })();

    /**
     * The ciphertext feedback mode of operation.
     */
    const cfb = (() => {

        /**
         * The CFB logic.
         */
        const logic = (() => {

            return {

                /**
                 * Encrypt some data with the CFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key       The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} iv        The initialization vector used for the encryption process.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                encrypt(key, plaintext, iv) {
                    const params = parameters.get_parameters(key, iv, plaintext, false);
                    let ciphertext = params.iv;
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        const encrypted_iv = rijndael.cipher(ciphertext.slice(i, i + STATE_SIZE), params.key, params.r);
                        params.data.slice(i, i + STATE_SIZE).map((x, j) => ciphertext.push(x ^ encrypted_iv[j]));
                    }
                    return ciphertext;
                },

                /**
                 * Decrypt some data with the CFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} ciphertext The ciphertext to decrypt.
                 * 
                 * @returns {number[]} The plaintext byte array.
                 */
                decrypt(key, ciphertext) {
                    const params = parameters.get_parameters(key, ciphertext.slice(0, STATE_SIZE), ciphertext.slice(STATE_SIZE), false);
                    let plaintext = [];
                    let current_iv = params.iv;
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        const encrypted_iv = rijndael.cipher(current_iv, params.key, params.r);
                        params.data.slice(i, i + STATE_SIZE).map((x, j) => plaintext.push(x ^ encrypted_iv[j]));
                        current_iv = params.data.slice(i, i + STATE_SIZE);
                    }
                    return plaintext;
                }

            }

        })();

        /**
         * The available encryption encodings.
         */
        const encrypt = (() => {

            return {

                /**
                 * Encrypt some data with the CFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key             The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext       The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]] The initialization vector used for the encryption process. A random IV is generated by default.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                array(key, plaintext, iv = utility.generate_CBC_CFB_IV()) {
                    return logic.encrypt(key, plaintext, iv);
                },

                /**
                 * Encrypt some data with the CFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key             The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext       The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]] The initialization vector used for the encryption process. A random IV is generated by default.
                 * 
                 * @returns {string} The ciphertext hex string.
                 */
                hex(key, plaintext, iv = utility.generate_CBC_CFB_IV()) {
                    return conversion.to_hex(this.array(key, plaintext, iv));
                },

                /**
                 * Encrypt some data with the CFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key             The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext       The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]] The initialization vector used for the encryption process. A random IV is generated by default.
                 * 
                 * @returns {string} The ciphertext Base64 string.
                 */
                base64(key, plaintext, iv = utility.generate_CBC_CFB_IV()) {
                    return conversion.to_base64(this.array(key, plaintext, iv));
                }

            }

        })();

        /**
         * The available decryption encodings.
         */
        const decrypt = (() => {

            /**
             * Decrypts a byte array to other encodings.
             */
            const array = (() => {

                return {

                    /**
                     * Decrypt a ciphertext byte array with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {number[]}                                     ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext) {
                        return logic.decrypt(key, ciphertext);
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {number[]}                                     ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext) {
                        return conversion.to_hex(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {number[]}                                     ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext) {
                        return conversion.to_base64(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {number[]}                                     ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext) {
                        return conversion.to_utf8(this.to_array(key, ciphertext));
                    }

                }

            })();

            /**
             * Decrypts a hex string to other encodings.
             */
            const hex = (() => {

                return {

                    /**
                     * Decrypt a ciphertext hex string with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext) {
                        return logic.decrypt(key, conversion.from_hex(ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext) {
                        return conversion.to_hex(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext) {
                        return conversion.to_base64(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext) {
                        return conversion.to_utf8(this.to_array(key, ciphertext));
                    }

                }

            })();

            /**
             * Decrypts a Base64 string to other encodings.
             */
            const base64 = (() => {

                return {

                    /**
                     * Decrypt a ciphertext Base64 string with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext) {
                        return logic.decrypt(key, conversion.from_base64(ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext) {
                        return conversion.to_hex(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext) {
                        return conversion.to_base64(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext) {
                        return conversion.to_utf8(this.to_array(key, ciphertext));
                    }

                }

            })();

            return {

                array: array,
                hex: hex,
                base64: base64

            }

        })();

        return {

            encrypt: encrypt,
            decrypt: decrypt

        }

    })();

    /**
     * The output feedback mode of operation.
     */
    const ofb = (() => {

        /**
         * The OFB logic.
         */
        const logic = (() => {

            return {

                /**
                 * Encrypt some data with the OFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key       The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} iv        The initialization vector used for the encryption process.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                encrypt(key, plaintext, iv) {
                    const params = parameters.get_parameters(key, iv, plaintext, false);
                    let ciphertext = params.iv;
                    let current_iv = params.iv;
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        current_iv = rijndael.cipher(current_iv, params.key, params.r);
                        params.data.slice(i, i + STATE_SIZE).map((x, j) => ciphertext.push(x ^ current_iv[j]));
                    }
                    return ciphertext;
                },

                /**
                 * Decrypt some data with the OFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} ciphertext The ciphertext to decrypt.
                 * 
                 * @returns {number[]} The plaintext byte array.
                 */
                decrypt(key, ciphertext) {
                    const params = parameters.get_parameters(key, ciphertext.slice(0, STATE_SIZE), ciphertext.slice(STATE_SIZE), false);
                    let plaintext = [];
                    let current_iv = params.iv;
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        current_iv = rijndael.cipher(current_iv, params.key, params.r);
                        params.data.slice(i, i + STATE_SIZE).map((x, j) => plaintext.push(x ^ current_iv[j]));
                    }
                    return plaintext;
                }

            }

        })();

        /**
         * The available encryption encodings.
         */
        const encrypt = (() => {

            return {

                /**
                 * Encrypt some data with the OFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key             The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext       The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]] The initialization vector used for the encryption process. A random IV is generated by default.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                array(key, plaintext, iv = utility.generate_OFB_IV()) {
                    return logic.encrypt(key, plaintext, iv);
                },

                /**
                 * Encrypt some data with the OFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key             The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext       The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]] The initialization vector used for the encryption process. A random IV is generated by default.
                 * 
                 * @returns {string} The ciphertext hex string.
                 */
                hex(key, plaintext, iv = utility.generate_OFB_IV()) {
                    return conversion.to_hex(this.array(key, plaintext, iv));
                },

                /**
                 * Encrypt some data with the OFB mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key             The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext       The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [iv = number[]] The initialization vector used for the encryption process. A random IV is generated by default.
                 * 
                 * @returns {string} The ciphertext Base64 string.
                 */
                base64(key, plaintext, iv = utility.generate_OFB_IV()) {
                    return conversion.to_base64(this.array(key, plaintext, iv));
                }

            }

        })();

        /**
         * The available decryption encodings.
         */
        const decrypt = (() => {

            /**
             * Decrypts a byte array to other encodings.
             */
            const array = (() => {

                return {

                    /**
                     * Decrypt a ciphertext byte array with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {number[]}                                     ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext) {
                        return logic.decrypt(key, ciphertext);
                    },

                    /**
                     * Decrypt a ciphertext byte array with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {number[]}                                     ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext) {
                        return conversion.to_hex(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {number[]}                                     ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext) {
                        return conversion.to_base64(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {number[]}                                     ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext) {
                        return conversion.to_utf8(this.to_array(key, ciphertext));
                    }

                }

            })();

            /**
             * Decrypts a hex string to other encodings.
             */
            const hex = (() => {

                return {

                    /**
                     * Decrypt a ciphertext hex string with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext) {
                        return logic.decrypt(key, conversion.from_hex(ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext) {
                        return conversion.to_hex(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext) {
                        return conversion.to_base64(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext) {
                        return conversion.to_utf8(this.to_array(key, ciphertext));
                    }

                }

            })();

            /**
             * Decrypts a Base64 string to other encodings.
             */
            const base64 = (() => {

                return {

                    /**
                     * Decrypt a ciphertext Base64 string with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext) {
                        return logic.decrypt(key, conversion.from_base64(ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext) {
                        return conversion.to_hex(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext) {
                        return conversion.to_base64(this.to_array(key, ciphertext));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the OFB mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key        The key used for the decryption process.
                     * @param {string}                                       ciphertext The ciphertext to decrypt.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext) {
                        return conversion.to_utf8(this.to_array(key, ciphertext));
                    }

                }

            })();

            return {

                array: array,
                hex: hex,
                base64: base64

            }

        })();

        return {

            encrypt: encrypt,
            decrypt: decrypt

        }

    })();

    /**
     * The counter mode of operation.
     */
    const ctr = (() => {

        /**
         * The CTR logic.
         */
        const logic = (() => {

            /**
             * Convert a 32 bit number to a byte array.
             * 
             * @param {number} n The number to convert.
             * 
             * @returns {number[]} The byte array.
             */
            const to_byte_counter = n => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

            return {

                /**
                 * Encrypt some data with the CTR mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key             The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} plaintext       The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} nonce           The number used once for the encryption process.
                 * @param {number}                                       initial_counter The initial counter to start the encryption process.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                encrypt(key, plaintext, nonce, initial_counter) {
                    const params = parameters.get_parameters_CTR(key, nonce, plaintext);
                    let ciphertext = params.nonce.slice();
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        const counter = params.nonce.concat(to_byte_counter(i / STATE_SIZE + initial_counter));
                        const stream = rijndael.cipher(counter, params.key, params.r);
                        params.data.slice(i, i + STATE_SIZE).map((x, j) => ciphertext.push(x ^ stream[j]));
                    }
                    return ciphertext;
                },

                /**
                 * Decrypt some data with the CTR mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer} key             The key used for the decryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer} ciphertext      The ciphertext to decrypt.
                 * @param {number}                                       initial_counter The initial counter to start the decryption process.
                 * 
                 * @returns {number[]} The plaintext byte array.
                 */
                decrypt(key, ciphertext, initial_counter) {
                    const params = parameters.get_parameters_CTR(key, ciphertext.slice(0, COUNTER_MODE_NONCE_LENGTH), ciphertext.slice(COUNTER_MODE_NONCE_LENGTH));
                    let plaintext = [];
                    for (let i = 0; i < params.data.length; i += STATE_SIZE) {
                        const counter = params.nonce.concat(to_byte_counter(i / STATE_SIZE + initial_counter));
                        const stream = rijndael.cipher(counter, params.key, params.r);
                        params.data.slice(i, i + STATE_SIZE).map((x, j) => plaintext.push(x ^ stream[j]));
                    }
                    return plaintext;
                }

            }

        })();

        /**
         * The available encryption encodings.
         */
        const encrypt = (() => {

            return {

                /**
                 * Encrypt some data with the CTR mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key                   The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext             The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [nonce = number[]]    The number used once for the encryption process. A random nonce is generated by default.
                 * @param {number | undefined}                                       [initial_counter = 0] The initial counter to start the encryption process. The default counter is 0.
                 * 
                 * @returns {number[]} The ciphertext byte array.
                 */
                array(key, plaintext, nonce = utility.generate_CTR_Nonce(), initial_counter = 0) {
                    return logic.encrypt(key, plaintext, nonce, initial_counter);
                },

                /**
                 * Encrypt some data with the CTR mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key                   The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext             The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [nonce = number[]]    The number used once for the encryption process. A random nonce is generated by default.
                 * @param {number | undefined}                                       [initial_counter = 0] The initial counter to start the encryption process. The default counter is 0.
                 * 
                 * @returns {string} The ciphertext hex string.
                 */
                hex(key, plaintext, nonce = utility.generate_CTR_Nonce(), initial_counter = 0) {
                    return conversion.to_hex(this.array(key, plaintext, nonce, initial_counter));
                },

                /**
                 * Encrypt some data with the CTR mode of operation.
                 * 
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             key                   The key used for the encryption process.
                 * @param {number[] | string | Uint8Array | ArrayBuffer}             plaintext             The plaintext to encrypt.
                 * @param {number[] | string | Uint8Array | ArrayBuffer | undefined} [nonce = number[]]    The number used once for the encryption process. A random nonce is generated by default.
                 * @param {number | undefined}                                       [initial_counter = 0] The initial counter to start the encryption process. The default counter is 0.
                 * 
                 * @returns {string} The ciphertext Base64 string.
                 */
                base64(key, plaintext, nonce = utility.generate_CTR_Nonce(), initial_counter = 0) {
                    return conversion.to_base64(this.array(key, plaintext, nonce, initial_counter));
                }

            }

        })();

        /**
         * The available decryption encodings.
         */
        const decrypt = (() => {

            /**
             * Decrypts a byte array to other encodings.
             */
            const array = (() => {

                return {

                    /**
                     * Decrypt a ciphertext byte array with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {number[]}                                     ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, initial_counter = 0) {
                        return logic.decrypt(key, ciphertext, initial_counter);
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {number[]}                                     ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, initial_counter = 0) {
                        return conversion.to_hex(this.to_array(key, ciphertext, initial_counter));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {number[]}                                     ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, initial_counter = 0) {
                        return conversion.to_base64(this.to_array(key, ciphertext, initial_counter));
                    },

                    /**
                     * Decrypt a ciphertext byte array with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {number[]}                                     ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, initial_counter = 0) {
                        return conversion.to_utf8(this.to_array(key, ciphertext, initial_counter));
                    }

                }

            })();

            /**
             * Decrypts a hex string to other encodings.
             */
            const hex = (() => {

                return {

                    /**
                     * Decrypt a ciphertext hex string with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {string}                                       ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, initial_counter = 0) {
                        return logic.decrypt(key, conversion.from_hex(ciphertext), initial_counter);
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {string}                                       ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, initial_counter = 0) {
                        return conversion.to_hex(this.to_array(key, ciphertext, initial_counter));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {string}                                       ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, initial_counter = 0) {
                        return conversion.to_base64(this.to_array(key, ciphertext, initial_counter));
                    },

                    /**
                     * Decrypt a ciphertext hex string with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {string}                                       ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, initial_counter = 0) {
                        return conversion.to_utf8(this.to_array(key, ciphertext, initial_counter));
                    }

                }

            })();

            /**
             * Decrypts a Base64 string to other encodings.
             */
            const base64 = (() => {

                return {

                    /**
                     * Decrypt a ciphertext Base64 string with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {string}                                       ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {number[]} The byte array plaintext.
                     */
                    to_array(key, ciphertext, initial_counter = 0) {
                        return logic.decrypt(key, conversion.from_base64(ciphertext), initial_counter);
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {string}                                       ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The hex string plaintext.
                     */
                    to_hex(key, ciphertext, initial_counter = 0) {
                        return conversion.to_hex(this.to_array(key, ciphertext, initial_counter));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {string}                                       ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The Base64 string plaintext.
                     */
                    to_base64(key, ciphertext, initial_counter = 0) {
                        return conversion.to_base64(this.to_array(key, ciphertext, initial_counter));
                    },

                    /**
                     * Decrypt a ciphertext Base64 string with the CTR mode of operation.
                     * 
                     * @param {number[] | string | Uint8Array | ArrayBuffer} key                   The key used for the decryption process.
                     * @param {string}                                       ciphertext            The ciphertext to decrypt.
                     * @param {number | undefined}                           [initial_counter = 0] The initial counter to start the decryption process. The default counter is 0.
                     * 
                     * @returns {string} The UTF-8 string plaintext.
                     */
                    to_utf8(key, ciphertext, initial_counter = 0) {
                        return conversion.to_utf8(this.to_array(key, ciphertext, initial_counter));
                    }

                }

            })();

            return {

                array: array,
                hex: hex,
                base64: base64

            }

        })();

        return {

            encrypt: encrypt,
            decrypt: decrypt

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
                    default: throw new Error(`Invalid data type '${type}' provided.`);
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
     * Utility functions used for the generation of initialization vector and nonces.
     */
    const utility = (() => {

        return {

            /**
             * Generate a CBC and CFB safe initialization vector.
             * 
             * @returns {number[]} The byte array initialization vector.
             */
            generate_CBC_CFB_IV() {
                const key = [].slice.call(crypto.getRandomValues(new Uint8Array(STATE_SIZE)));
                const seed = [].slice.call(crypto.getRandomValues(new Uint8Array(STATE_SIZE)));
                return ecb.encrypt.array(key, seed, false);
            },

            /**
             * Generate a OFB safe initialization vector.
             * 
             * @returns {number[]} The byte array initialization vector.
             */
            generate_OFB_IV() {
                const key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
                const seed = conversion.from_hex(Date.now().toString(16).padStart(STATE_SIZE * 2, '0'));                
                return ecb.encrypt.array(key, seed, false);
            },

            /**
             * Generate a CTR safe initialization vector.
             * 
             * @returns {number[]} The byte array initialization vector.
             */
            generate_CTR_Nonce() {
                return this.generate_OFB_IV().slice(0, COUNTER_MODE_NONCE_LENGTH);
            }

        }

    })();

    /**
     * The rijndael primitive.
     */
    const primitive = (() => {

        return {

            rijndael: rijndael

        }

    })();

    return {

        ecb: ecb,
        cbc: cbc,
        cfb: cfb,
        ofb: ofb,
        ctr: ctr,
        primitive: primitive

    }

})();