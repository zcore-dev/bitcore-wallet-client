'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
var common_1 = require("./common");
var $ = require('preconditions').singleton();
var _ = require('lodash');
var Bitcore = require('bitcore-lib');
var Mnemonic = require('bitcore-mnemonic');
var sjcl = require('sjcl');
var Credentials = (function () {
    function Credentials() {
        this.version = 2;
        this.account = 0;
    }
    Credentials.fromDerivedKey = function (opts) {
        $.shouldBeString(opts.coin);
        $.shouldBeString(opts.network);
        $.shouldBeNumber(opts.account, 'Invalid account');
        $.shouldBeString(opts.xPubKey, 'Invalid xPubKey');
        $.shouldBeString(opts.rootPath, 'Invalid rootPath');
        $.shouldBeString(opts.keyId, 'Invalid keyId');
        $.shouldBeString(opts.requestPrivKey, 'Invalid requestPrivKey');
        $.checkArgument(_.isUndefined(opts.nonCompliantDerivation));
        opts = opts || {};
        var x = new Credentials();
        x.coin = opts.coin;
        x.network = opts.network;
        x.account = opts.account;
        x.n = opts.n;
        x.xPubKey = opts.xPubKey;
        x.keyId = opts.keyId;
        if (_.isUndefined(opts.addressType)) {
            x.addressType =
                opts.n == 1
                    ? common_1.Constants.SCRIPT_TYPES.P2PKH
                    : common_1.Constants.SCRIPT_TYPES.P2SH;
        }
        else {
            x.addressType = opts.addressType;
        }
        x.rootPath = opts.rootPath;
        if (opts.walletPrivKey) {
            x.addWalletPrivateKey(opts.walletPrivKey);
        }
        x.requestPrivKey = opts.requestPrivKey;
        var priv = Bitcore.PrivateKey(x.requestPrivKey);
        x.requestPubKey = priv.toPublicKey().toString();
        var prefix = 'personalKey';
        var entropySource = Bitcore.crypto.Hash.sha256(priv.toBuffer()).toString('hex');
        var b = Buffer.from(entropySource, 'hex');
        var b2 = Bitcore.crypto.Hash.sha256hmac(b, Buffer.from(prefix));
        x.personalEncryptingKey = b2.slice(0, 16).toString('base64');
        x.copayerId = common_1.Utils.xPubToCopayerId(x.coin, x.xPubKey);
        x.publicKeyRing = [
            {
                xPubKey: x.xPubKey,
                requestPubKey: x.requestPubKey
            }
        ];
        return x;
    };
    Credentials.prototype.getRootPath = function () {
        var _this = this;
        var legacyRootPath = function () {
            var purpose;
            switch (_this.derivationStrategy) {
                case common_1.Constants.DERIVATION_STRATEGIES.BIP45:
                    return "m/45'";
                case common_1.Constants.DERIVATION_STRATEGIES.BIP44:
                    purpose = '44';
                    break;
                case common_1.Constants.DERIVATION_STRATEGIES.BIP48:
                    purpose = '48';
                    break;
            }
            var coin = '0';
            if (_this.network != 'livenet' && _this.coin !== 'eth') {
                coin = '1';
            }
            else if (_this.coin == 'bch') {
                if (_this.use145forBCH) {
                    coin = '145';
                }
                else {
                    coin = '0';
                }
            }
            else if (_this.coin == 'btc') {
                coin = '0';
            }
            else if (_this.coin == 'eth') {
                coin = '60';
            }
            else {
                throw new Error('unknown coin: ' + _this.coin);
            }
            return 'm/' + purpose + "'/" + coin + "'/" + _this.account + "'";
        };
        if (!this.rootPath) {
            this.rootPath = legacyRootPath();
        }
        return this.rootPath;
    };
    Credentials.fromObj = function (obj) {
        var x = new Credentials();
        if (!obj.version || obj.version < x.version) {
            throw new Error('Obsolete credentials version');
        }
        if (obj.version != x.version) {
            throw new Error('Bad credentials version');
        }
        _.each(Credentials.FIELDS, function (k) {
            x[k] = obj[k];
        });
        if (x.externalSource) {
            throw new Error('External Wallets are no longer supported');
        }
        x.coin = x.coin || 'btc';
        x.addressType = x.addressType || common_1.Constants.SCRIPT_TYPES.P2SH;
        x.account = x.account || 0;
        $.checkState(x.xPrivKey || x.xPubKey || x.xPrivKeyEncrypted, 'invalid input');
        return x;
    };
    Credentials.prototype.toObj = function () {
        var self = this;
        var x = {};
        _.each(Credentials.FIELDS, function (k) {
            x[k] = self[k];
        });
        return x;
    };
    Credentials.prototype.addWalletPrivateKey = function (walletPrivKey) {
        this.walletPrivKey = walletPrivKey;
        this.sharedEncryptingKey = common_1.Utils.privateKeyToAESKey(walletPrivKey);
    };
    Credentials.prototype.addWalletInfo = function (walletId, walletName, m, n, copayerName, opts) {
        opts = opts || {};
        this.walletId = walletId;
        this.walletName = walletName;
        this.m = m;
        if (this.n != n && !opts.allowOverwrite) {
            if (this.n == 1 || n == 1) {
                throw new Error("Bad nr of copayers in addWalletInfo: this: " + this.n + " got: " + n);
            }
        }
        this.n = n;
        if (copayerName)
            this.copayerName = copayerName;
        if (n == 1) {
            this.addPublicKeyRing([
                {
                    xPubKey: this.xPubKey,
                    requestPubKey: this.requestPubKey
                }
            ]);
        }
    };
    Credentials.prototype.hasWalletInfo = function () {
        return !!this.walletId;
    };
    Credentials.prototype.addPublicKeyRing = function (publicKeyRing) {
        this.publicKeyRing = _.clone(publicKeyRing);
    };
    Credentials.prototype.isComplete = function () {
        if (!this.m || !this.n)
            return false;
        if (!this.publicKeyRing || this.publicKeyRing.length != this.n)
            return false;
        return true;
    };
    Credentials.FIELDS = [
        'coin',
        'network',
        'xPrivKey',
        'xPrivKeyEncrypted',
        'xPubKey',
        'requestPrivKey',
        'requestPubKey',
        'copayerId',
        'publicKeyRing',
        'walletId',
        'walletName',
        'm',
        'n',
        'walletPrivKey',
        'personalEncryptingKey',
        'sharedEncryptingKey',
        'copayerName',
        'externalSource',
        'mnemonic',
        'mnemonicEncrypted',
        'entropySource',
        'mnemonicHasPassphrase',
        'derivationStrategy',
        'account',
        'compliantDerivation',
        'addressType',
        'hwInfo',
        'entropySourcePath',
        'use145forBCH',
        'version',
        'rootPath',
        'keyId'
    ];
    return Credentials;
}());
exports.Credentials = Credentials;
//# sourceMappingURL=credentials.js.map