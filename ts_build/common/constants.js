'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.Constants = {
    SCRIPT_TYPES: {
        P2SH: 'P2SH',
        P2PKH: 'P2PKH',
    },
    DERIVATION_STRATEGIES: {
        BIP44: 'BIP44',
        BIP45: 'BIP45',
        BIP48: 'BIP48',
    },
    PATHS: {
        SINGLE_ADDRESS: 'm/0/0',
        REQUEST_KEY: "m/1'/0",
        REQUEST_KEY_AUTH: 'm/2',
    },
    BIP45_SHARED_INDEX: 0x80000000 - 1,
    UNITS: {
        btc: {
            toSatoshis: 100000000,
            full: {
                maxDecimals: 8,
                minDecimals: 8,
            },
            short: {
                maxDecimals: 6,
                minDecimals: 2,
            }
        },
        bch: {
            toSatoshis: 100000000,
            full: {
                maxDecimals: 8,
                minDecimals: 8,
            },
            short: {
                maxDecimals: 6,
                minDecimals: 2,
            }
        },
        eth: {
            toSatoshis: 1e18,
            full: {
                maxDecimals: 8,
                minDecimals: 8,
            },
            short: {
                maxDecimals: 6,
                minDecimals: 2,
            }
        },
        bit: {
            toSatoshis: 100,
            full: {
                maxDecimals: 2,
                minDecimals: 2,
            },
            short: {
                maxDecimals: 0,
                minDecimals: 0,
            }
        },
    },
    COINS: ['btc', 'bch', 'eth'],
    UTXO_COINS: ['btc', 'bch']
};
//# sourceMappingURL=constants.js.map