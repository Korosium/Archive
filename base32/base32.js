"use strict";
/**
 * JavaScript implementation of the Base32 encoding scheme.
 * 
 * Base32 is the base-32 numeral system. It uses a set of 32 digits, each of which can be represented by 5 bits (2^5).
 * One way to represent Base32 numbers in a human-readable way is by using a standard 32-character set, 
 * such as the twenty-two upper-case letters A–V and the digits 0-9. 
 * However, many other variations are used in different contexts. (from Wikipedia)
 * 
 * @link   https://en.wikipedia.org/wiki/Base32
 * @link   https://datatracker.ietf.org/doc/html/rfc4648
 * @file   This file defines the base32 global constant.
 * @author Korosium
 */
const base32 = (() => {

    /**
     * All the possible alphabet for Base32.
     */
    const alphabet = (() => {

        /**
         * The original alphabet.
         */
        const RFC_4648_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        /**
         * The extended hexadecimal alphabet.
         */
        const BASE_32_HEX_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

        /**
         * Alphabet created by Zooko Wilcox-O'Hearn.
         */
        const Z_BASE_32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";

        /**
         * Alphabet created by Douglas Crockford to avoid obscenity.
         */
        const CROCKFORD_BASE_32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        return {

            RFC_4648_ALPHABET: RFC_4648_ALPHABET,
            BASE_32_HEX_ALPHABET: BASE_32_HEX_ALPHABET,
            Z_BASE_32_ALPHABET: Z_BASE_32_ALPHABET,
            CROCKFORD_BASE_32_ALPHABET: CROCKFORD_BASE_32_ALPHABET

        }

    })();

    /**
     * To encode data to a Base32 string.
     */
    const encoding = (() => {

        /**
         * Convert the input to a byte array.
         * 
         * @param {number[] | string | Uint8Array | ArrayBuffer} data The input to convert.
         * 
         * @returns {number[]} The byte array.
         */
        const to_byte = data => {
            const type = Object.prototype.toString.call(data);
            switch (type) {
                case "[object Array]": return data.slice();
                case "[object String]": return [].slice.call(new TextEncoder().encode(data));
                case "[object Uint8Array]": return [].slice.call(data);
                case "[object ArrayBuffer]": return [].slice.call(new Uint8Array(data));
                default: throw new Error(`Invalid data type "${type}" provided.`);
            }
        };

        /**
         * Convert a slice of the byte array to it's quintet equivalent.
         * 
         * @param {number[]} bytes The slice of the byte array to convert.
         * 
         * @returns {number[]} The quintet array.
         */
        const slice_to_quintet = bytes => {
            const length = bytes.length;
            for (let i = length; i < 5; i++) {
                bytes[i] = 0;
            }
            let retval = [];
            if (length > 0) {
                retval[retval.length] = (bytes[0] >>> 3) & 0x1f;
                retval[retval.length] = ((bytes[0] << 2) | (bytes[1] >>> 6)) & 0x1f;
            }
            if (length > 1) {
                retval[retval.length] = (bytes[1] >>> 1) & 0x1f;
                retval[retval.length] = ((bytes[1] << 4) | (bytes[2] >>> 4)) & 0x1f;
            }
            if (length > 2) {
                retval[retval.length] = ((bytes[2] << 1) | (bytes[3] >>> 7)) & 0x1f;
            }
            if (length > 3) {
                retval[retval.length] = (bytes[3] >>> 2) & 0x1f;
                retval[retval.length] = ((bytes[3] << 3) | (bytes[4] >>> 5)) & 0x1f;
            }
            if (length > 4) {
                retval[retval.length] = bytes[4] & 0x1f;
            }
            return retval;
        };

        /**
         * Convert the byte array to it's quintet equivalent.
         * 
         * @param {number[]} bytes The byte array to convert.
         * 
         * @returns {number[]} The new quintet array.
         */
        const bytes_to_quintet = bytes => {
            let all = [];
            for (let i = 0; i < bytes.length; i += 5) {
                const quintet = slice_to_quintet(bytes.slice(i, i + 5));
                for (let j = 0; j < quintet.length; j++) {
                    all[all.length] = quintet[j];
                }
            }
            return all;
        };

        /**
         * Convert the quintet array with the appropriate alphabet.
         * 
         * @param {number[]} quintet  The quintet array to convert.
         * @param {string}   alphabet The chosen alphabet.
         * 
         * @returns {string} The Base32 encoded string.
         */
        const quintet_to_alphabet = (quintet, alphabet) => {
            let retval = "";
            for (let i = 0; i < quintet.length; i++) {
                retval += alphabet[quintet[i]];
            }
            return retval;
        };

        /**
         * Pad the encoded string if need be.
         * 
         * @param {string}  encoded The Base32 encoded string.
         * @param {boolean} padding Does the string need to be padded?
         * 
         * @returns {string} The Base32 encoded string.
         */
        const pad = (encoded, padding) => {
            if (encoded.length === 0) return "";
            if (padding && encoded.length % 8 !== 0) {
                for (let i = encoded.length % 8; i < 8; i++) {
                    encoded += "=";
                }
            }
            return encoded;
        };

        /**
         * Change the encoded string to lower case if need be.
         * 
         * @param {string}  encoded   The Base32 encoded string.
         * @param {boolean} lowercase Does the string need to be lower case?
         * 
         * @returns {string} The Base32 encoded string.
         */
        const to_lower_case = (encoded, lowercase) => {
            if (lowercase) return encoded.toLowerCase();
            return encoded;
        };

        return {

            /**
             * Encode the input data to get it's Base32 encoded string equivalent.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data      The data to encode.
             * @param {string}                                       alphabet  The chosen alphabet.
             * @param {boolean}                                      padding   Does the string need to be padded?
             * @param {boolean}                                      lowercase Does the string need to be lower case?
             * 
             * @returns {string} The Base32 encoded string.
             */
            process(data, alphabet, padding, lowercase) {
                return to_lower_case(pad(quintet_to_alphabet(bytes_to_quintet(to_byte(data)), alphabet), padding), lowercase);
            }

        }

    })();

    /**
     * To decode a Base32 string to a different encoding. 
     */
    const decoding = (() => {

        /**
         * Convert the Base32 encoded string to it's quintet equivalent.
         * 
         * @param {string} encoded  The Base32 encoded string.
         * @param {string} alphabet The chosen alphabet.
         * 
         * @returns {number[]} The quintet array.
         */
        const alphabet_to_quintet = (encoded, alphabet) => {
            encoded = encoded.replaceAll("=", "");
            let retval = [];
            for (let i = 0; i < encoded.length; i++) {
                retval[i] = alphabet.indexOf(encoded[i]);
            }
            return retval;
        };

        /**
         * Convert a slice of the quintet array to it's byte equivalent.
         * 
         * @param {number[]} quintet The slice of the quintet array to convert.
         * 
         * @returns {number[]} The byte array.
         */
        const slice_to_bytes = quintet => {
            const length = quintet.length;
            for (let i = length; i < 8; i++) {
                quintet[i] = 0;
            }
            let retval = [];
            retval[retval.length] = ((quintet[0] << 3) | (quintet[1] >> 2)) & 0xff;
            if (length > 2) retval[retval.length] = ((quintet[1] << 6) | (quintet[2] << 1) | (quintet[3] >>> 4)) & 0xff;
            if (length > 4) retval[retval.length] = ((quintet[3] << 4) | (quintet[4] >> 1)) & 0xff;
            if (length > 5) retval[retval.length] = ((quintet[4] << 7) | (quintet[5] << 2) | (quintet[6] >>> 3)) & 0xff;
            if (length > 7) retval[retval.length] = ((quintet[6] << 5) | (quintet[7])) & 0xff;
            return retval;
        };

        /**
         * Convert the quintet array to it's byte array equivalent.
         * 
         * @param {number[]} quintet The quintet array to convert.
         * 
         * @returns {number[]} The byte array.
         */
        const quintet_to_bytes = quintet => {
            let all = [];
            for (let i = 0; i < quintet.length; i += 8) {
                const bytes = slice_to_bytes(quintet.slice(i, i + 8));
                for (let j = 0; j < bytes.length; j++) {
                    all[all.length] = bytes[j];
                }
            }
            return all;
        };

        return {

            /**
             * Decode a Base32 encoded string to it's byte array equivalent.
             * 
             * @param {string} data     The Base32 encoded string.
             * @param {string} alphabet The chosen alphabet.
             * 
             * @returns {number[]} The byte array data.
             */
            to_array(data, alphabet) {
                return quintet_to_bytes(alphabet_to_quintet(data.toLowerCase(), alphabet.toLowerCase()));
            },

            /**
             * Decode a Base32 encoded string to it's hex string equivalent.
             * 
             * @param {string} data     The Base32 encoded string.
             * @param {string} alphabet The chosen alphabet.
             * 
             * @returns {string} The hex string data.
             */
            to_hex(data, alphabet) {
                return this.to_array(data, alphabet).map(x => x.toString(16).padStart(2, '0')).join('');
            },

            /**
             * Decode a Base32 encoded string to it's Base64 string equivalent.
             * 
             * @param {string} data     The Base32 encoded string.
             * @param {string} alphabet The chosen alphabet.
             * 
             * @returns {string} The Base64 string data.
             */
            to_base64(data, alphabet) {
                return btoa(this.to_array(data, alphabet).map(x => String.fromCharCode(x)).join(''));
            },

            /**
             * Decode a Base32 encoded string to it's UTF-8 string equivalent.
             * 
             * @param {string} data     The Base32 encoded string.
             * @param {string} alphabet The chosen alphabet.
             * 
             * @returns {string} The UTF-8 string data.
             */
            to_utf8(data, alphabet) {
                return new TextDecoder().decode(new Uint8Array(this.to_array(data, alphabet)).buffer);
            }

        }

    })();

    /**
     * To encode and decode data using the RFC-4648 alphabet.
     */
    const RFC_4648 = (() => {

        /**
         * To decode RFC-4648 encoded strings.
         */
        const decode = (() => {

            return {

                /**
                 * Decode a Base32 encoded string to it's byte array equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {number[]} The byte array data.
                 */
                to_array(data) {
                    return decoding.to_array(data, alphabet.RFC_4648_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's hex string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The hex string data.
                 */
                to_hex(data) {
                    return decoding.to_hex(data, alphabet.RFC_4648_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's Base64 string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The Base64 string data.
                 */
                to_base64(data) {
                    return decoding.to_base64(data, alphabet.RFC_4648_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's UTF-8 string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The UTF-8 string data.
                 */
                to_utf8(data) {
                    return decoding.to_utf8(data, alphabet.RFC_4648_ALPHABET);
                }

            }

        })();

        return {

            /**
             * Encode the input data to get it's Base32 encoded string equivalent.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data                The data to encode.
             * @param {boolean | undefined}                          [padding = true]    Does the string need to be padded?
             * @param {boolean | undefined}                          [lowercase = false] Does the string need to be lower case?
             * 
             * @returns {string} The Base32 encoded string.
             */
            encode(data, padding = true, lowercase = false) {
                return encoding.process(data, alphabet.RFC_4648_ALPHABET, padding, lowercase);
            },

            decode: decode

        }

    })();

    /**
     * To encode and decode data using the base32hex alphabet.
     */
    const BASE_32_HEX = (() => {

        /**
         * To decode base32hex encoded strings.
         */
        const decode = (() => {

            return {

                /**
                 * Decode a Base32 encoded string to it's byte array equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {number[]} The byte array data.
                 */
                to_array(data) {
                    return decoding.to_array(data, alphabet.BASE_32_HEX_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's hex string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The hex string data.
                 */
                to_hex(data) {
                    return decoding.to_hex(data, alphabet.BASE_32_HEX_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's Base64 string equivalent.
                 * 
                 * @param {strinbase64g} data The Base32 encoded string.
                 * 
                 * @returns {string} The Base64 string data.
                 */
                to_base64(data) {
                    return decoding.to_base64(data, alphabet.BASE_32_HEX_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's UTF-8 string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The UTF-8 string data.
                 */
                to_utf8(data) {
                    return decoding.to_utf8(data, alphabet.BASE_32_HEX_ALPHABET);
                }

            }

        })();

        return {

            /**
             * Encode the input data to get it's Base32 encoded string equivalent.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data                The data to encode.
             * @param {boolean | undefined}                          [padding = true]    Does the string need to be padded?
             * @param {boolean | undefined}                          [lowercase = false] Does the string need to be lower case?
             * 
             * @returns {string} The Base32 encoded string.
             */
            encode(data, padding = true, lowercase = false) {
                return encoding.process(data, alphabet.BASE_32_HEX_ALPHABET, padding, lowercase);
            },

            decode: decode

        }

    })();

    /**
     * To encode and decode data using the z-base-32 alphabet.
     */
    const Z_BASE_32 = (() => {

        /**
         * To decode z-base-32 encoded strings.
         */
        const decode = (() => {

            return {

                /**
                 * Decode a Base32 encoded string to it's byte array equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {number[]} The byte array data.
                 */
                to_array(data) {
                    return decoding.to_array(data, alphabet.Z_BASE_32_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's hex string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The hex string data.
                 */
                to_hex(data) {
                    return decoding.to_hex(data, alphabet.Z_BASE_32_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's Base64 string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The Base64 string data.
                 */
                to_base64(data) {
                    return decoding.to_base64(data, alphabet.Z_BASE_32_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's UTF-8 string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The UTF-8 string data.
                 */
                to_utf8(data) {
                    return decoding.to_utf8(data, alphabet.Z_BASE_32_ALPHABET);
                }

            }

        })();

        return {

            /**
             * Encode the input data to get it's Base32 encoded string equivalent.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data The data to encode.
             * 
             * @returns {string} The Base32 encoded string.
             */
            encode(data) {
                return encoding.process(data, alphabet.Z_BASE_32_ALPHABET, false, true);
            },

            decode: decode

        }

    })();

    /**
     * To encode and decode data using the Crockford's Base32 alphabet.
     */
    const CROCKFORD_BASE_32 = (() => {

        /**
         * Change all the "o", "i" and "l" to "0", "1" respectively.
         * 
         * @param {string} encoded The Base32 encoded string.
         * 
         * @returns {string} The formatted Base32 encoded string.
         */
        const formatData = encoded => {
            encoded = encoded.toLowerCase();
            encoded = encoded.replaceAll("o", "0");
            encoded = encoded.replaceAll("i", "1");
            encoded = encoded.replaceAll("l", "1");
            return encoded;
        };

        /**
         * To decode Crockford's Base32 encoded strings.
         */
        const decode = (() => {

            return {

                /**
                 * Decode a Base32 encoded string to it's byte array equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {number[]} The byte array data.
                 */
                to_array(data) {
                    return decoding.to_array(formatData(data), alphabet.CROCKFORD_BASE_32_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's hex string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The hex string data.
                 */
                to_hex(data) {
                    return decoding.to_hex(formatData(data), alphabet.CROCKFORD_BASE_32_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's Base64 string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The Base64 string data.
                 */
                to_base64(data) {
                    return decoding.to_base64(formatData(data), alphabet.CROCKFORD_BASE_32_ALPHABET);
                },

                /**
                 * Decode a Base32 encoded string to it's UTF-8 string equivalent.
                 * 
                 * @param {string} data The Base32 encoded string.
                 * 
                 * @returns {string} The UTF-8 string data.
                 */
                to_utf8(data) {
                    return decoding.to_utf8(formatData(data), alphabet.CROCKFORD_BASE_32_ALPHABET);
                }

            }

        })();

        return {

            /**
             * Encode the input data to get it's Base32 encoded string equivalent.
             * 
             * @param {number[] | string | Uint8Array | ArrayBuffer} data                The data to encode.
             * @param {boolean | undefined}                          [lowercase = false] Does the string need to be lower case?
             * 
             * @returns {string} The Base32 encoded string.
             */
            encode(data, lowercase = false) {
                return encoding.process(data, alphabet.CROCKFORD_BASE_32_ALPHABET, false, lowercase);
            },

            decode: decode

        }

    })();

    return {

        alphabet: alphabet,
        RFC_4648: RFC_4648,
        BASE_32_HEX: BASE_32_HEX,
        Z_BASE_32: Z_BASE_32,
        CROCKFORD_BASE_32: CROCKFORD_BASE_32

    }

})();