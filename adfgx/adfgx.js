"use strict";
/**
 * JavaScript implementation of the ADFGX and the ADFGVX algorithms.
 * 
 * Invented by the Germans signal corps officers Lieutenant Fritz Nebel (1891–1977) 
 * and introduced in March 1918 with the designation "Secret Cipher of the Radio Operators 1918" 
 * (Geheimschrift der Funker 1918, in short GedeFu 18), the cipher was a fractionating transposition 
 * cipher which combined a modified Polybius square with a single columnar transposition. 
 * 
 * @link   https://en.wikipedia.org/wiki/ADFGVX_cipher
 * @file   This file defines the adfgx global constant.
 * @author Korosium
 */
const adfgx = (() => {

    /**
     * The base Polybius square of the ADFGX cipher.
     */
    const BASE_POLYBIUS = "ADFGX";

    /**
     * The base Polybius square of the ADFGVX cipher.
     */
    const EXTENDED_POLYBIUS = "ADFGVX";

    /**
     * The default alphabet of the ADFGX cipher.
     */
    const DEFAULT_25_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

    /**
     * The default alphabet of the ADFGVX cipher.
     */
    const DEFAULT_36_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /**
     * The padding character when a column is lesser than the column width.
     */
    const PAD_CHAR = '*';

    /**
     * Fractionate the plaintext with the Polybius square.
     * 
     * @param {string} plaintext       The plaintext to fractionate.
     * @param {string} alphabet        The alphabet to get the Polybius square postion from.
     * @param {string} polybius_square The Polybius square for the specific algorithm.
     * 
     * @returns {string} The fractionated plaintext.
     */
    const fractionate = (plaintext, alphabet, polybius_square) => {
        let retval = "";
        for (let i = 0; i < plaintext.length; i++) {
            const n = alphabet.indexOf(plaintext[i]);
            if (n !== -1) { // Only the chars in the alphabet are allowed.
                const first = Math.floor(n / polybius_square.length);
                const second = Math.floor(n % polybius_square.length);
                const fractionated = `${polybius_square[first]}${polybius_square[second]}`;
                retval += fractionated;
            }
        }
        return retval;
    };

    /**
     * Perform a columnar transposition using the key.
     * 
     * @param {string[]} key          The key to transpose the fractionated plaintext with.
     * @param {string}   fractionated The fractionated plaintext.
     * 
     * @returns {string[]} The columnar transposed plaintext.
     */
    const column_transpose = (key, fractionated) => {
        let retval = [];
        for (let i = 0; i < key.length; i++) retval[i] = "";
        for (let i = 0; i < fractionated.length; i++) {
            retval[i % key.length] += fractionated[i];
        }
        return retval;
    };

    /**
     * Perform an alphabetical transposition using the key.
     * 
     * @param {string[]} key               The key to sort the columnar transposed plaintext with.
     * @param {string}   column_transposed The columnar transposed plaintext.
     * 
     * @returns {string} The ciphertext.
     */
    const alpha_transpose = (key, column_transposed) => {
        let retval = "";
        const ordered_key = key.slice().sort();
        for (let i = 0; i < ordered_key.length; i++) {
            retval += column_transposed[key.indexOf(ordered_key[i])];
        }
        return retval;
    };

    /**
     * Get the amount of chars that are per columns. Helps a ton to rearange the ciphertext in the right order.
     * 
     * @param {string[]} key        The key to create the ordered key.
     * @param {number}   full_width The full width of a padded/max capacity column.
     * @param {number}   missing    The amount of missing pad char.
     * 
     * @returns {number[]} The amount of chars per columns.
     */
    const get_column_lengths = (key, full_width, missing) => {
        let retval = [];
        const ordered_key = key.slice().sort();
        for (let i = 0; i < key.length; i++) {
            const j = key.indexOf(ordered_key[i]);
            if (j >= key.length - missing) {
                retval[i] = full_width - 1;
            }
            else {
                retval[i] = full_width;
            }
        }
        return retval;
    };

    /**
     * Rearange the ciphertext into it's original padded form.
     * 
     * @param {string[]} key        The key used to rearange the ciphertext with it's padding.
     * @param {string}   ciphertext The ciphertext to rearange to it's padded form.
     * 
     * @returns The padded ciphertext.
     */
    const reverse_alpha_transpose = (key, ciphertext) => {
        // Calculate how many columns have to be padded.
        let missing = key.length - (ciphertext.length % key.length);
        if (missing === key.length) missing = 0;
        const full_width = (ciphertext.length + missing) / key.length;

        // Get all columns lengths.
        const col_lengths = get_column_lengths(key, full_width, missing);

        // Get all the column with the needed pad characters.
        let retval = [];
        for (let i = 0; i < col_lengths.length; i++) {
            let length = 0;
            for (let j = 0; j < i; j++) {
                length += col_lengths[j];
            }
            const slice = ciphertext.slice(length, length + col_lengths[i]);
            if (col_lengths[i] < full_width) {
                retval[i] = slice + PAD_CHAR;
            }
            else {
                retval[i] = slice;
            }
        }
        return retval.toString().replaceAll(',', '');
    };

    /**
     * Rearange the ciphertext to it's fractionated form.
     * 
     * @param {string} key        The key used to rearange the ciphertext to it's fractionated form with.
     * @param {string} ciphertext The ciphertext to rearanged to it's fractionated form.
     * 
     * @returns {string} The fractionated ciphertext.
     */
    const reverse_column_transpose = (key, ciphertext) => {
        const ordered_key = key.slice().sort();
        let retval = "";
        const width = ciphertext.length / key.length;
        for (let y = 0; y < width; y++) {
            for (let x = 0; x < key.length; x++) {
                retval += ciphertext[ordered_key.indexOf(key[x]) * width + y];
            }
        }
        return retval.replaceAll(PAD_CHAR, '');
    };

    /**
     * Get the plaintext back from the transposed ciphertext.
     * 
     * @param {string} ciphertext      The transposed ciphertext to get the plaintext from.
     * @param {string} alphabet        The alphabet to get the plaintext from the ciphertext.
     * @param {string} polybius_square The Polybius square used to get the char position in the alphabet.
     * 
     * @returns {string} The plaintext.
     */
    const reverse_fractionate = (ciphertext, alphabet, polybius_square) => {
        let retval = "";
        for (let i = 0; i < ciphertext.length; i += 2) {
            const first = polybius_square.indexOf(ciphertext[i]);
            const second = polybius_square.indexOf(ciphertext[i + 1]);
            retval += alphabet[first * polybius_square.length + second];
        }
        return retval;
    };

    /**
     * Check for duplicate chars.
     * 
     * @param {string} s The string to check for duplicate chars.
     * 
     * @returns {string[]} The array of all the duplicate chars.
     */
    const check_for_duplicate_chars = s => {
        let retval = [];
        for (let i = 0; i < s.length; i++) {
            for (let j = 0; j < s.length; j++) {
                if (s[j] === s[i] && i !== j) {
                    if (retval.indexOf(s[j]) === -1) {
                        retval[retval.length] = s[j];
                    }
                }
            }
        }
        return retval;
    };

    /**
     * Remove all the duplicate chars in a string.
     * 
     * @param {string} s The string to remove the duplicate chars from.
     * 
     * @returns {string} The string with no duplicate chars.
     */
    const remove_duplicate = s => {
        const duplicate = check_for_duplicate_chars(s);
        for (let i = 0; i < duplicate.length; i++) {
            const j = s.indexOf(duplicate[i]);
            s = s.replaceAll(duplicate[i], "");
            s = s.slice(0, j) + duplicate[i] + s.slice(j);
        }
        return s;
    };

    /**
     * Choose the right Polybius square based on the alphabet length.
     * 
     * @param {string} alphabet The alphabet to check the length of.
     * 
     * @returns {string} The right Polybius square.
     */
    const choose_polybius_square = alphabet => {
        let retval = "";
        if (alphabet.length === 36) {
            retval = EXTENDED_POLYBIUS;
        }
        else {
            retval = BASE_POLYBIUS;
        }
        return retval;
    };

    /**
     * Pad the alphabet with the default alphabet if chars are missing.
     * 
     * @param {string} alphabet         The alphabet to pad.
     * @param {string} default_alphabet The chosen default alphabet.
     * 
     * @returns {string} The padded alphabet.
     */
    const pad_alphabet = (alphabet, default_alphabet) => {
        let missing_chars = [];
        for (let i = 0; i < default_alphabet.length; i++) {
            if (alphabet.indexOf(default_alphabet[i]) === -1) {
                missing_chars[missing_chars.length] = default_alphabet[i];
            }
        }
        for (let i = 0; i < missing_chars.length; i++) {
            alphabet += missing_chars[i];
        }
        return alphabet;
    };

    /**
     * Format the inputs so that they are of the right format for the cipher.
     * 
     * @param {string} key      The key to format.
     * @param {string} text     Either the plaintext or the ciphertext to format.
     * @param {string} alphabet The alphabet to format and pad.
     * 
     * @returns {Object} Returns the key, the text, the alphabet and the Polybius square.
     */
    const format_inputs = (key, text, alphabet) => {
        // Convert everything to upper case and remove the duplicate chars for the key and the alphabet.
        text = text.toUpperCase().trim();
        key = remove_duplicate(key.toUpperCase().trim()).split('');
        alphabet = only_alphabet_char(remove_duplicate(alphabet.toUpperCase().trim()));

        // Pad the alphabet if some chars are missing whilst respecting the respective ADFGX and ADFGVX rules respectively.
        if (alphabet.length > DEFAULT_25_ALPHABET.length && alphabet.length < DEFAULT_36_ALPHABET.length) {
            alphabet = pad_alphabet(alphabet, DEFAULT_36_ALPHABET);
        }
        else if (alphabet.length < DEFAULT_25_ALPHABET.length) {
            alphabet = alphabet.replaceAll('J', 'I');
            alphabet = pad_alphabet(alphabet, DEFAULT_25_ALPHABET);
        }

        // Replace all 'J' to 'I' to respect the original ADFGX rule.
        if (alphabet.length === DEFAULT_25_ALPHABET.length) {
            text = text.replaceAll('J', 'I');
        }

        // Choose the Polybius square based on the alphabet length.
        const polybius_square = choose_polybius_square(alphabet);

        // Return all the formated inputs.
        return { key: key, text: text, alphabet: alphabet, polybius_square: polybius_square };
    };

    /**
     * Remove all none alphabet legal char from the string.
     * 
     * @param {string} s The alphabet string.
     * 
     * @returns {string} The sanitized alphabet.
     */
    const only_alphabet_char = s => {
        let alphabet = DEFAULT_25_ALPHABET;
        if(s.length > DEFAULT_25_ALPHABET.length) alphabet = DEFAULT_36_ALPHABET;
        let retval = "";
        for(let i = 0; i < s.length; i++){
            if(alphabet.indexOf(s[i]) !== -1){
                retval += s[i];
            }
        }
        return retval;
    };

    /**
     * Get a randomly safe integer between min (included) and max (excluded).
     * 
     * @param {number} min The minimum possible value (included).
     * @param {number} max The maximum possible value (excluded).
     * 
     * @returns {number} The safe random integer.
     */
    const rng = (min, max) => {
        const seed = crypto.getRandomValues(new Uint32Array(1))[0];
        const rand = seed / 2 ** 32;
        return Math.floor(rand * (max - min)) + min;
    };

    return {

        /**
         * Encrypt the plaintext with the ADFGX or ADFGVX cipher.
         * 
         * @param {string}        key       The key to encrypt the plaintext with.
         * @param {string}        plaintext The plaintext to encrypt.
         * @param {string | null} alphabet  The alphabet to encrypt the plaintext with. If no alphabet is provided the function will generate a 36 chars long random string and will use the ADFGVX mode.
         * 
         * @returns {Object} Returns both the ciphertext and the alphabet.
         */
        encrypt(key, plaintext, alphabet = this.generate_alphabet(true)) {
            const inputs = format_inputs(key, plaintext, alphabet);
            const ciphertext = alpha_transpose(inputs["key"], column_transpose(inputs["key"], fractionate(inputs["text"], inputs["alphabet"], inputs["polybius_square"])));
            return { ciphertext: ciphertext, alphabet: inputs["alphabet"] };
        },

        /**
         * Decrypt the ciphertext with the ADFGX or ADFGVX cipher.
         * 
         * @param {string} key        The key to decrypt the ciphertext with.
         * @param {string} ciphertext The ciphertext to decrypt.
         * @param {string} alphabet   The alphabet to decrypt the ciphertext with.
         * 
         * @returns {string} The plaintext.
         */
        decrypt(key, ciphertext, alphabet) {
            const inputs = format_inputs(key, ciphertext, alphabet);
            const plaintext = reverse_fractionate(reverse_column_transpose(inputs["key"], reverse_alpha_transpose(inputs["key"], inputs["text"])), inputs["alphabet"], inputs["polybius_square"]);
            return plaintext;
        },

        /**
         * Generate a new alphabet.
         * 
         * @param {boolean} extended If true generate a ADFGVX valid alphabet. Otherwise generate a ADFGX valid alphabet.
         * 
         * @returns {string} The generated alphabet.
         */
        generate_alphabet(extended = false) {
            let alphabet = DEFAULT_25_ALPHABET;
            if (extended) alphabet = DEFAULT_36_ALPHABET;
            const length = alphabet.length;
            let retval = "";
            for (let i = 0; i < length; i++) {
                const j = rng(0, alphabet.length);
                retval += alphabet[j];
                alphabet = alphabet.slice(0, j) + alphabet.slice(j + 1);
            }
            return retval;
        }

    }

})();