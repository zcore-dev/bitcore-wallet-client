'use strict';
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var $ = require('preconditions').singleton();
var _ = __importStar(require("lodash"));
var common_1 = require("./common");
var credentials_1 = require("./credentials");
var crypto_wallet_core_1 = require("crypto-wallet-core");
var Bitcore = require('bitcore-lib');
var Mnemonic = require('bitcore-mnemonic');
var sjcl = require('sjcl');
var log = require('./log');
var async = require('async');
var Uuid = require('uuid');
var Errors = require('./errors');
var wordsForLang = {
    en: Mnemonic.Words.ENGLISH,
    es: Mnemonic.Words.SPANISH,
    ja: Mnemonic.Words.JAPANESE,
    zh: Mnemonic.Words.CHINESE,
    fr: Mnemonic.Words.FRENCH,
    it: Mnemonic.Words.ITALIAN
};
var NETWORK = 'livenet';
var Key = (function () {
    function Key() {
        this.toObj = function () {
            var self = this;
            var x = {};
            _.each(Key.FIELDS, function (k) {
                x[k] = self[k];
            });
            return x;
        };
        this.isPrivKeyEncrypted = function () {
            return !!this.xPrivKeyEncrypted && !this.xPrivKey;
        };
        this.checkPassword = function (password) {
            if (this.isPrivKeyEncrypted()) {
                try {
                    sjcl.decrypt(password, this.xPrivKeyEncrypted);
                }
                catch (ex) {
                    return false;
                }
                return true;
            }
            return null;
        };
        this.get = function (password) {
            var keys = {};
            var fingerPrintUpdated = false;
            if (this.isPrivKeyEncrypted()) {
                $.checkArgument(password, 'Private keys are encrypted, a password is needed');
                try {
                    keys.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);
                    if (!this.fingerPrint) {
                        var xpriv = new Bitcore.HDPrivateKey(keys.xPrivKey);
                        this.fingerPrint = xpriv.fingerPrint.toString('hex');
                        fingerPrintUpdated = true;
                    }
                    if (this.mnemonicEncrypted) {
                        keys.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
                    }
                }
                catch (ex) {
                    throw new Error('Could not decrypt');
                }
            }
            else {
                keys.xPrivKey = this.xPrivKey;
                keys.mnemonic = this.mnemonic;
                if (fingerPrintUpdated) {
                    keys.fingerPrintUpdated = true;
                }
            }
            return keys;
        };
        this.encrypt = function (password, opts) {
            if (this.xPrivKeyEncrypted)
                throw new Error('Private key already encrypted');
            if (!this.xPrivKey)
                throw new Error('No private key to encrypt');
            this.xPrivKeyEncrypted = sjcl.encrypt(password, this.xPrivKey, opts);
            if (!this.xPrivKeyEncrypted)
                throw new Error('Could not encrypt');
            if (this.mnemonic)
                this.mnemonicEncrypted = sjcl.encrypt(password, this.mnemonic, opts);
            delete this.xPrivKey;
            delete this.mnemonic;
        };
        this.decrypt = function (password) {
            if (!this.xPrivKeyEncrypted)
                throw new Error('Private key is not encrypted');
            try {
                this.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);
                if (this.mnemonicEncrypted) {
                    this.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
                }
                delete this.xPrivKeyEncrypted;
                delete this.mnemonicEncrypted;
            }
            catch (ex) {
                log.error('error decrypting:', ex);
                throw new Error('Could not decrypt');
            }
        };
        this.derive = function (password, path) {
            $.checkArgument(path, 'no path at derive()');
            var xPrivKey = new Bitcore.HDPrivateKey(this.get(password).xPrivKey, NETWORK);
            var deriveFn = this.compliantDerivation
                ? _.bind(xPrivKey.deriveChild, xPrivKey)
                : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);
            return deriveFn(path);
        };
        this.createCredentials = function (password, opts) {
            opts = opts || {};
            if (password)
                $.shouldBeString(password, 'provide password');
            this._checkCoin(opts.coin);
            this._checkNetwork(opts.network);
            $.shouldBeNumber(opts.account, 'Invalid account');
            $.shouldBeNumber(opts.n, 'Invalid n');
            $.shouldBeUndefined(opts.useLegacyCoinType);
            $.shouldBeUndefined(opts.useLegacyPurpose);
            var path = this.getBaseAddressDerivationPath(opts);
            var xPrivKey = this.derive(password, path);
            var requestPrivKey = this.derive(password, common_1.Constants.PATHS.REQUEST_KEY).privateKey.toString();
            if (opts.network == 'testnet') {
                var x = xPrivKey.toObject();
                x.network = 'testnet';
                delete x.xprivkey;
                delete x.checksum;
                x.privateKey = _.padStart(x.privateKey, 64, '0');
                xPrivKey = new Bitcore.HDPrivateKey(x);
            }
            return credentials_1.Credentials.fromDerivedKey({
                xPubKey: xPrivKey.hdPublicKey.toString(),
                coin: opts.coin,
                network: opts.network,
                account: opts.account,
                n: opts.n,
                rootPath: path,
                keyId: this.id,
                requestPrivKey: requestPrivKey,
                addressType: opts.addressType,
                walletPrivKey: opts.walletPrivKey
            });
        };
        this.createAccess = function (password, opts) {
            opts = opts || {};
            $.shouldBeString(opts.path);
            var requestPrivKey = new Bitcore.PrivateKey(opts.requestPrivKey || null);
            var requestPubKey = requestPrivKey.toPublicKey().toString();
            var xPriv = this.derive(password, opts.path);
            var signature = common_1.Utils.signRequestPubKey(requestPubKey, xPriv);
            requestPrivKey = requestPrivKey.toString();
            return {
                signature: signature,
                requestPrivKey: requestPrivKey
            };
        };
        this.sign = function (rootPath, txp, password, cb) {
            $.shouldBeString(rootPath);
            if (this.isPrivKeyEncrypted() && !password) {
                return cb(new Errors.ENCRYPTED_PRIVATE_KEY());
            }
            var privs = [];
            var derived = {};
            var derived = this.derive(password, rootPath);
            var xpriv = new Bitcore.HDPrivateKey(derived);
            var t = common_1.Utils.buildTx(txp);
            if (common_1.Constants.UTXO_COINS.includes(txp.coin)) {
                _.each(txp.inputs, function (i) {
                    $.checkState(i.path, 'Input derivation path not available (signing transaction)');
                    if (!derived[i.path]) {
                        derived[i.path] = xpriv.deriveChild(i.path).privateKey;
                        privs.push(derived[i.path]);
                    }
                });
                var signatures = _.map(privs, function (priv, i) {
                    return t.getSignatures(priv);
                });
                signatures = _.map(_.sortBy(_.flatten(signatures), 'inputIndex'), function (s) {
                    return s.signature.toDER().toString('hex');
                });
                return signatures;
            }
            else {
                var addressPath = common_1.Constants.PATHS.SINGLE_ADDRESS;
                var privKey = xpriv.deriveChild(addressPath).privateKey;
                var tx = t.uncheckedSerialize();
                var signedRawTx = crypto_wallet_core_1.Transactions.sign({
                    chain: txp.coin.toUpperCase(),
                    tx: tx,
                    key: { privKey: privKey.toString('hex') },
                    from: txp.from
                });
                return Object.assign(txp, { rawTx: signedRawTx, status: 'accepted' });
            }
        };
        this.version = 1;
        this.use0forBCH = false;
        this.use44forMultisig = false;
        this.compliantDerivation = true;
        this.id = Uuid.v4();
    }
    Key.match = function (a, b) {
        return a.id == b.id;
    };
    Key.prototype._checkCoin = function (coin) {
        if (!_.includes(common_1.Constants.COINS, coin))
            throw new Error('Invalid coin');
    };
    Key.prototype._checkNetwork = function (network) {
        if (!_.includes(['livenet', 'testnet'], network))
            throw new Error('Invalid network');
    };
    Key.prototype.getBaseAddressDerivationPath = function (opts) {
        $.checkArgument(opts, 'Need to provide options');
        $.checkArgument(opts.n >= 1, 'n need to be >=1');
        var purpose = opts.n == 1 || this.use44forMultisig ? '44' : '48';
        var coinCode = '0';
        if (opts.network == 'testnet' && opts.coin !== 'eth') {
            coinCode = '1';
        }
        else if (opts.coin == 'bch') {
            if (this.use0forBCH) {
                coinCode = '0';
            }
            else {
                coinCode = '145';
            }
        }
        else if (opts.coin == 'btc') {
            coinCode = '0';
        }
        else if (opts.coin == 'eth') {
            coinCode = '60';
        }
        else {
            throw new Error('unknown coin: ' + opts.coin);
        }
        return 'm/' + purpose + "'/" + coinCode + "'/" + opts.account + "'";
    };
    Key.FIELDS = [
        'xPrivKey',
        'xPrivKeyEncrypted',
        'mnemonic',
        'mnemonicEncrypted',
        'mnemonicHasPassphrase',
        'fingerPrint',
        'compliantDerivation',
        'BIP45',
        'use0forBCH',
        'use44forMultisig',
        'version',
        'id'
    ];
    Key.create = function (opts) {
        opts = opts || {};
        if (opts.language && !wordsForLang[opts.language])
            throw new Error('Unsupported language');
        var m = new Mnemonic(wordsForLang[opts.language]);
        while (!Mnemonic.isValid(m.toString())) {
            m = new Mnemonic(wordsForLang[opts.language]);
        }
        var x = new Key();
        var xpriv = m.toHDPrivateKey(opts.passphrase, NETWORK);
        x.xPrivKey = xpriv.toString();
        x.fingerPrint = xpriv.fingerPrint.toString('hex');
        x.mnemonic = m.phrase;
        x.mnemonicHasPassphrase = !!opts.passphrase;
        x.use0forBCH = opts.useLegacyCoinType;
        x.use44forMultisig = opts.useLegacyPurpose;
        x.compliantDerivation = !opts.nonCompliantDerivation;
        return x;
    };
    Key.fromMnemonic = function (words, opts) {
        $.checkArgument(words);
        if (opts)
            $.shouldBeObject(opts);
        opts = opts || {};
        var m = new Mnemonic(words);
        var x = new Key();
        var xpriv = m.toHDPrivateKey(opts.passphrase, NETWORK);
        x.xPrivKey = xpriv.toString();
        x.fingerPrint = xpriv.fingerPrint.toString('hex');
        x.mnemonic = words;
        x.mnemonicHasPassphrase = !!opts.passphrase;
        x.use0forBCH = opts.useLegacyCoinType;
        x.use44forMultisig = opts.useLegacyPurpose;
        x.compliantDerivation = !opts.nonCompliantDerivation;
        return x;
    };
    Key.fromExtendedPrivateKey = function (xPriv, opts) {
        $.checkArgument(xPriv);
        opts = opts || {};
        var xpriv;
        try {
            xpriv = new Bitcore.HDPrivateKey(xPriv);
        }
        catch (e) {
            throw new Error('Invalid argument');
        }
        var x = new Key();
        x.xPrivKey = xpriv.toString();
        x.fingerPrint = xpriv.fingerPrint.toString('hex');
        x.mnemonic = null;
        x.mnemonicHasPassphrase = null;
        x.use44forMultisig = opts.useLegacyPurpose;
        x.use0forBCH = opts.useLegacyCoinType;
        x.compliantDerivation = !opts.nonCompliantDerivation;
        return x;
    };
    Key.fromObj = function (obj) {
        $.shouldBeObject(obj);
        var x = new Key();
        if (obj.version != x.version) {
            throw new Error('Bad Key version');
        }
        _.each(Key.FIELDS, function (k) {
            x[k] = obj[k];
        });
        $.checkState(x.xPrivKey || x.xPrivKeyEncrypted, 'invalid input');
        return x;
    };
    return Key;
}());
exports.Key = Key;
//# sourceMappingURL=key.js.map