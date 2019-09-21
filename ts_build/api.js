'use strict';
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var CWC = __importStar(require("crypto-wallet-core"));
var events_1 = require("events");
var lodash_1 = __importDefault(require("lodash"));
var sjcl_1 = __importDefault(require("sjcl"));
var common_1 = require("./common");
var credentials_1 = require("./credentials");
var key_1 = require("./key");
var paypro_1 = require("./paypro");
var request_1 = require("./request");
var verifier_1 = require("./verifier");
var $ = require('preconditions').singleton();
var util = require('util');
var async = require('async');
var events = require('events');
var Bitcore = require('bitcore-lib');
var Bitcore_ = {
    btc: Bitcore,
    bch: require('bitcore-lib-cash'),
    eth: Bitcore
};
var Mnemonic = require('bitcore-mnemonic');
var url = require('url');
var querystring = require('querystring');
var log = require('./log');
var Errors = require('./errors');
var BASE_URL = 'http://localhost:3232/bws/api';
var API = (function (_super) {
    __extends(API, _super);
    function API(opts) {
        var _this = _super.call(this) || this;
        opts = opts || {};
        _this.doNotVerifyPayPro = opts.doNotVerifyPayPro;
        _this.timeout = opts.timeout || 50000;
        _this.logLevel = opts.logLevel || 'silent';
        _this.supportStaffWalletId = opts.supportStaffWalletId;
        _this.bp_partner = opts.bp_partner;
        _this.bp_partner_version = opts.bp_partner_version;
        _this.request = new request_1.Request(opts.baseUrl || BASE_URL, { r: opts.request });
        log.setLevel(_this.logLevel);
        return _this;
    }
    API.prototype.initNotifications = function (cb) {
        log.warn('DEPRECATED: use initialize() instead.');
        this.initialize({}, cb);
    };
    API.prototype.initialize = function (opts, cb) {
        $.checkState(this.credentials);
        this.notificationIncludeOwn = !!opts.notificationIncludeOwn;
        this._initNotifications(opts);
        return cb();
    };
    API.prototype.dispose = function (cb) {
        this._disposeNotifications();
        this.request.logout(cb);
    };
    API.prototype._fetchLatestNotifications = function (interval, cb) {
        var _this = this;
        cb = cb || function () { };
        var opts = {
            lastNotificationId: this.lastNotificationId,
            includeOwn: this.notificationIncludeOwn
        };
        if (!this.lastNotificationId) {
            opts.timeSpan = interval + 1;
        }
        this.getNotifications(opts, function (err, notifications) {
            if (err) {
                log.warn('Error receiving notifications.');
                log.debug(err);
                return cb(err);
            }
            if (notifications.length > 0) {
                _this.lastNotificationId = lodash_1.default.last(notifications).id;
            }
            lodash_1.default.each(notifications, function (notification) {
                _this.emit('notification', notification);
            });
            return cb();
        });
    };
    API.prototype._initNotifications = function (opts) {
        var _this = this;
        opts = opts || {};
        var interval = opts.notificationIntervalSeconds || 5;
        this.notificationsIntervalId = setInterval(function () {
            _this._fetchLatestNotifications(interval, function (err) {
                if (err) {
                    if (err instanceof Errors.NOT_FOUND ||
                        err instanceof Errors.NOT_AUTHORIZED) {
                        _this._disposeNotifications();
                    }
                }
            });
        }, interval * 1000);
    };
    API.prototype._disposeNotifications = function () {
        if (this.notificationsIntervalId) {
            clearInterval(this.notificationsIntervalId);
            this.notificationsIntervalId = null;
        }
    };
    API.prototype.setNotificationsInterval = function (notificationIntervalSeconds) {
        this._disposeNotifications();
        if (notificationIntervalSeconds > 0) {
            this._initNotifications({
                notificationIntervalSeconds: notificationIntervalSeconds
            });
        }
    };
    API.prototype.getRootPath = function () {
        return this.credentials.getRootPath();
    };
    API._encryptMessage = function (message, encryptingKey) {
        if (!message)
            return null;
        return common_1.Utils.encryptMessage(message, encryptingKey);
    };
    API.prototype._processTxNotes = function (notes) {
        if (!notes)
            return;
        var encryptingKey = this.credentials.sharedEncryptingKey;
        lodash_1.default.each([].concat(notes), function (note) {
            note.encryptedBody = note.body;
            note.body = common_1.Utils.decryptMessageNoThrow(note.body, encryptingKey);
            note.encryptedEditedByName = note.editedByName;
            note.editedByName = common_1.Utils.decryptMessageNoThrow(note.editedByName, encryptingKey);
        });
    };
    API.prototype._processTxps = function (txps) {
        var _this = this;
        if (!txps)
            return;
        var encryptingKey = this.credentials.sharedEncryptingKey;
        lodash_1.default.each([].concat(txps), function (txp) {
            txp.encryptedMessage = txp.message;
            txp.message =
                common_1.Utils.decryptMessageNoThrow(txp.message, encryptingKey) || null;
            txp.creatorName = common_1.Utils.decryptMessageNoThrow(txp.creatorName, encryptingKey);
            lodash_1.default.each(txp.actions, function (action) {
                action.copayerName = common_1.Utils.decryptMessageNoThrow(action.copayerName, encryptingKey);
                action.comment = common_1.Utils.decryptMessageNoThrow(action.comment, encryptingKey);
            });
            lodash_1.default.each(txp.outputs, function (output) {
                output.encryptedMessage = output.message;
                output.message =
                    common_1.Utils.decryptMessageNoThrow(output.message, encryptingKey) || null;
            });
            txp.hasUnconfirmedInputs = lodash_1.default.some(txp.inputs, function (input) {
                return input.confirmations == 0;
            });
            _this._processTxNotes(txp.note);
        });
    };
    API.prototype.validateKeyDerivation = function (opts, cb) {
        var _deviceValidated;
        opts = opts || {};
        var c = this.credentials;
        var testMessageSigning = function (xpriv, xpub) {
            var nonHardenedPath = 'm/0/0';
            var message = 'Lorem ipsum dolor sit amet, ne amet urbanitas percipitur vim, libris disputando his ne, et facer suavitate qui. Ei quidam laoreet sea. Cu pro dico aliquip gubergren, in mundi postea usu. Ad labitur posidonium interesset duo, est et doctus molestie adipiscing.';
            var priv = xpriv.deriveChild(nonHardenedPath).privateKey;
            var signature = common_1.Utils.signMessage(message, priv);
            var pub = xpub.deriveChild(nonHardenedPath).publicKey;
            return common_1.Utils.verifyMessage(message, signature, pub);
        };
        var testHardcodedKeys = function () {
            var words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
            var xpriv = Mnemonic(words).toHDPrivateKey();
            if (xpriv.toString() !=
                'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu')
                return false;
            xpriv = xpriv.deriveChild("m/44'/0'/0'");
            if (xpriv.toString() !=
                'xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb')
                return false;
            var xpub = Bitcore.HDPublicKey.fromString('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj');
            return testMessageSigning(xpriv, xpub);
        };
        var testLiveKeys = function () {
            var words;
            try {
                words = c.getMnemonic();
            }
            catch (ex) { }
            var xpriv;
            if (words && (!c.mnemonicHasPassphrase || opts.passphrase)) {
                var m = new Mnemonic(words);
                xpriv = m.toHDPrivateKey(opts.passphrase, c.network);
            }
            if (!xpriv) {
                xpriv = new Bitcore.HDPrivateKey(c.xPrivKey);
            }
            xpriv = xpriv.deriveChild(c.getBaseAddressDerivationPath());
            var xpub = new Bitcore.HDPublicKey(c.xPubKey);
            return testMessageSigning(xpriv, xpub);
        };
        var hardcodedOk = true;
        if (!_deviceValidated && !opts.skipDeviceValidation) {
            hardcodedOk = testHardcodedKeys();
            _deviceValidated = true;
        }
        this.keyDerivationOk = hardcodedOk;
        return cb(null, this.keyDerivationOk);
    };
    API.prototype.toString = function (opts) {
        $.checkState(this.credentials);
        $.checkArgument(!this.noSign, 'no Sign not supported');
        $.checkArgument(!this.password, 'password not supported');
        opts = opts || {};
        var output;
        var c = credentials_1.Credentials.fromObj(this.credentials);
        output = JSON.stringify(c.toObj());
        return output;
    };
    API.prototype.fromString = function (credentials) {
        try {
            if (!lodash_1.default.isObject(credentials) || !credentials.xPubKey) {
                credentials = credentials_1.Credentials.fromObj(JSON.parse(credentials));
            }
            this.credentials = credentials;
        }
        catch (ex) {
            log.warn("Error importing wallet: " + ex);
            if (ex.toString().match(/Obsolete/)) {
                throw new Errors.OBSOLETE_BACKUP();
            }
            else {
                throw new Errors.INVALID_BACKUP();
            }
        }
        this.request.setCredentials(this.credentials);
    };
    API.prototype.decryptBIP38PrivateKey = function (encryptedPrivateKeyBase58, passphrase, opts, cb) {
        var Bip38 = require('bip38');
        var bip38 = new Bip38();
        var privateKeyWif;
        try {
            privateKeyWif = bip38.decrypt(encryptedPrivateKeyBase58, passphrase);
        }
        catch (ex) {
            return cb(new Error('Could not decrypt BIP38 private key' + ex));
        }
        var privateKey = new Bitcore.PrivateKey(privateKeyWif);
        var address = privateKey.publicKey.toAddress().toString();
        var addrBuff = Buffer.from(address, 'ascii');
        var actualChecksum = Bitcore.crypto.Hash.sha256sha256(addrBuff)
            .toString('hex')
            .substring(0, 8);
        var expectedChecksum = Bitcore.encoding.Base58Check.decode(encryptedPrivateKeyBase58)
            .toString('hex')
            .substring(6, 14);
        if (actualChecksum != expectedChecksum)
            return cb(new Error('Incorrect passphrase'));
        return cb(null, privateKeyWif);
    };
    API.prototype.getBalanceFromPrivateKey = function (privateKey, coin, cb) {
        if (lodash_1.default.isFunction(coin)) {
            cb = coin;
            coin = 'btc';
        }
        var B = Bitcore_[coin];
        var privateKey = new B.PrivateKey(privateKey);
        var address = privateKey.publicKey.toAddress().toString(true);
        this.getUtxos({
            addresses: address
        }, function (err, utxos) {
            if (err)
                return cb(err);
            return cb(null, lodash_1.default.sumBy(utxos, 'satoshis'));
        });
    };
    API.prototype.buildTxFromPrivateKey = function (privateKey, destinationAddress, opts, cb) {
        var _this = this;
        opts = opts || {};
        var coin = opts.coin || 'btc';
        var B = Bitcore_[coin];
        var privateKey = B.PrivateKey(privateKey);
        var address = privateKey.publicKey.toAddress().toString(true);
        async.waterfall([
            function (next) {
                _this.getUtxos({
                    addresses: address
                }, function (err, utxos) {
                    return next(err, utxos);
                });
            },
            function (utxos, next) {
                if (!lodash_1.default.isArray(utxos) || utxos.length == 0)
                    return next(new Error('No utxos found'));
                var fee = opts.fee || 10000;
                var amount = lodash_1.default.sumBy(utxos, 'satoshis') - fee;
                if (amount <= 0)
                    return next(new Errors.INSUFFICIENT_FUNDS());
                var tx;
                try {
                    var toAddress = B.Address.fromString(destinationAddress);
                    tx = new B.Transaction()
                        .from(utxos)
                        .to(toAddress, amount)
                        .fee(fee)
                        .sign(privateKey);
                    tx.serialize();
                }
                catch (ex) {
                    log.error('Could not build transaction from private key', ex);
                    return next(new Errors.COULD_NOT_BUILD_TRANSACTION());
                }
                return next(null, tx);
            }
        ], cb);
    };
    API.prototype.openWallet = function (opts, cb) {
        var _this = this;
        if (lodash_1.default.isFunction(opts)) {
            cb = opts;
        }
        opts = opts || {};
        $.checkState(this.credentials);
        if (this.credentials.isComplete() && this.credentials.hasWalletInfo())
            return cb(null, true);
        var qs = [];
        qs.push('includeExtendedInfo=1');
        qs.push('serverMessageArray=1');
        this.request.get('/v3/wallets/?' + qs.join('&'), function (err, ret) {
            if (err)
                return cb(err);
            var wallet = ret.wallet;
            _this._processStatus(ret);
            if (!_this.credentials.hasWalletInfo()) {
                var me = lodash_1.default.find(wallet.copayers, {
                    id: _this.credentials.copayerId
                });
                if (!me)
                    return cb(new Error('Copayer not in wallet'));
                try {
                    _this.credentials.addWalletInfo(wallet.id, wallet.name, wallet.m, wallet.n, me.name, opts);
                }
                catch (e) {
                    if (e.message) {
                        log.info('Trying credentials...', e.message);
                    }
                    if (e.message && e.message.match(/Bad\snr/)) {
                        return cb(new Errors.WALLET_DOES_NOT_EXIST());
                    }
                    throw e;
                }
            }
            if (wallet.status != 'complete')
                return cb();
            if (_this.credentials.walletPrivKey) {
                if (!verifier_1.Verifier.checkCopayers(_this.credentials, wallet.copayers)) {
                    return cb(new Errors.SERVER_COMPROMISED());
                }
            }
            else {
                log.warn('Could not verify copayers key (missing wallet Private Key)');
            }
            _this.credentials.addPublicKeyRing(_this._extractPublicKeyRing(wallet.copayers));
            _this.emit('walletCompleted', wallet);
            return cb(null, ret);
        });
    };
    API._buildSecret = function (walletId, walletPrivKey, coin, network) {
        if (lodash_1.default.isString(walletPrivKey)) {
            walletPrivKey = Bitcore.PrivateKey.fromString(walletPrivKey);
        }
        var widHex = Buffer.from(walletId.replace(/-/g, ''), 'hex');
        var widBase58 = new Bitcore.encoding.Base58(widHex).toString();
        return (lodash_1.default.padEnd(widBase58, 22, '0') +
            walletPrivKey.toWIF() +
            (network == 'testnet' ? 'T' : 'L') +
            coin);
    };
    API.parseSecret = function (secret) {
        $.checkArgument(secret);
        var split = function (str, indexes) {
            var parts = [];
            indexes.push(str.length);
            var i = 0;
            while (i < indexes.length) {
                parts.push(str.substring(i == 0 ? 0 : indexes[i - 1], indexes[i]));
                i++;
            }
            return parts;
        };
        try {
            var secretSplit = split(secret, [22, 74, 75]);
            var widBase58 = secretSplit[0].replace(/0/g, '');
            var widHex = Bitcore.encoding.Base58.decode(widBase58).toString('hex');
            var walletId = split(widHex, [8, 12, 16, 20]).join('-');
            var walletPrivKey = Bitcore.PrivateKey.fromString(secretSplit[1]);
            var networkChar = secretSplit[2];
            var coin = secretSplit[3] || 'btc';
            return {
                walletId: walletId,
                walletPrivKey: walletPrivKey,
                coin: coin,
                network: networkChar == 'T' ? 'testnet' : 'livenet'
            };
        }
        catch (ex) {
            throw new Error('Invalid secret');
        }
    };
    API.getRawTx = function (txp) {
        var t = common_1.Utils.buildTx(txp);
        return t.uncheckedSerialize();
    };
    API.prototype._getCurrentSignatures = function (txp) {
        var acceptedActions = lodash_1.default.filter(txp.actions, {
            type: 'accept'
        });
        return lodash_1.default.map(acceptedActions, function (x) {
            return {
                signatures: x.signatures,
                xpub: x.xpub
            };
        });
    };
    API.prototype._addSignaturesToBitcoreTx = function (txp, t, signatures, xpub) {
        if (signatures.length != txp.inputs.length)
            throw new Error('Number of signatures does not match number of inputs');
        $.checkState(txp.coin);
        var bitcore = Bitcore_[txp.coin];
        var i = 0, x = new bitcore.HDPublicKey(xpub);
        lodash_1.default.each(signatures, function (signatureHex) {
            var input = txp.inputs[i];
            try {
                var signature = bitcore.crypto.Signature.fromString(signatureHex);
                var pub = x.deriveChild(txp.inputPaths[i]).publicKey;
                var s = {
                    inputIndex: i,
                    signature: signature,
                    sigtype: bitcore.crypto.Signature.SIGHASH_ALL |
                        bitcore.crypto.Signature.SIGHASH_FORKID,
                    publicKey: pub
                };
                t.inputs[i].addSignature(t, s);
                i++;
            }
            catch (e) { }
        });
        if (i != txp.inputs.length)
            throw new Error('Wrong signatures');
    };
    API.prototype._applyAllSignatures = function (txp, t) {
        var _this = this;
        $.checkState(txp.status == 'accepted');
        var sigs = this._getCurrentSignatures(txp);
        lodash_1.default.each(sigs, function (x) {
            _this._addSignaturesToBitcoreTx(txp, t, x.signatures, x.xpub);
        });
    };
    API.prototype._doJoinWallet = function (walletId, walletPrivKey, xPubKey, requestPubKey, copayerName, opts, cb) {
        var _this = this;
        $.shouldBeFunction(cb);
        opts = opts || {};
        opts.customData = opts.customData || {};
        opts.customData.walletPrivKey = walletPrivKey.toString();
        var encCustomData = common_1.Utils.encryptMessage(JSON.stringify(opts.customData), this.credentials.personalEncryptingKey);
        var encCopayerName = common_1.Utils.encryptMessage(copayerName, this.credentials.sharedEncryptingKey);
        var args = {
            walletId: walletId,
            coin: opts.coin,
            name: encCopayerName,
            xPubKey: xPubKey,
            requestPubKey: requestPubKey,
            customData: encCustomData
        };
        if (opts.dryRun)
            args.dryRun = true;
        if (lodash_1.default.isBoolean(opts.supportBIP44AndP2PKH))
            args.supportBIP44AndP2PKH = opts.supportBIP44AndP2PKH;
        var hash = common_1.Utils.getCopayerHash(args.name, args.xPubKey, args.requestPubKey);
        args.copayerSignature = common_1.Utils.signMessage(hash, walletPrivKey);
        var url = '/v2/wallets/' + walletId + '/copayers';
        this.request.post(url, args, function (err, body) {
            if (err)
                return cb(err);
            _this._processWallet(body.wallet);
            return cb(null, body.wallet);
        });
    };
    API.prototype.isComplete = function () {
        return this.credentials && this.credentials.isComplete();
    };
    API.prototype._extractPublicKeyRing = function (copayers) {
        return lodash_1.default.map(copayers, function (copayer) {
            var pkr = lodash_1.default.pick(copayer, ['xPubKey', 'requestPubKey']);
            pkr.copayerName = copayer.name;
            return pkr;
        });
    };
    API.prototype.getFeeLevels = function (coin, network, cb) {
        $.checkArgument(coin || lodash_1.default.includes(common_1.Constants.COINS, coin));
        $.checkArgument(network || lodash_1.default.includes(['livenet', 'testnet'], network));
        this.request.get('/v2/feelevels/?coin=' +
            (coin || 'btc') +
            '&network=' +
            (network || 'livenet'), function (err, result) {
            if (err)
                return cb(err);
            return cb(err, result);
        });
    };
    API.prototype.getVersion = function (cb) {
        this.request.get('/v1/version/', cb);
    };
    API.prototype._checkKeyDerivation = function () {
        var isInvalid = this.keyDerivationOk === false;
        if (isInvalid) {
            log.error('Key derivation for this device is not working as expected');
        }
        return !isInvalid;
    };
    API.prototype.createWallet = function (walletName, copayerName, m, n, opts, cb) {
        var _this = this;
        if (!this._checkKeyDerivation())
            return cb(new Error('Cannot create new wallet'));
        if (opts)
            $.shouldBeObject(opts);
        opts = opts || {};
        var coin = opts.coin || 'btc';
        if (!lodash_1.default.includes(common_1.Constants.COINS, coin))
            return cb(new Error('Invalid coin'));
        var network = opts.network || 'livenet';
        if (!lodash_1.default.includes(['testnet', 'livenet'], network))
            return cb(new Error('Invalid network'));
        if (!this.credentials) {
            return cb(new Error('Import credentials first with setCredentials()'));
        }
        if (coin != this.credentials.coin) {
            return cb(new Error('Existing keys were created for a different coin'));
        }
        if (network != this.credentials.network) {
            return cb(new Error('Existing keys were created for a different network'));
        }
        var walletPrivKey = opts.walletPrivKey || new Bitcore.PrivateKey();
        var c = this.credentials;
        c.addWalletPrivateKey(walletPrivKey.toString());
        var encWalletName = common_1.Utils.encryptMessage(walletName, c.sharedEncryptingKey);
        var args = {
            name: encWalletName,
            m: m,
            n: n,
            pubKey: new Bitcore.PrivateKey(walletPrivKey).toPublicKey().toString(),
            coin: coin,
            network: network,
            singleAddress: !!opts.singleAddress,
            id: opts.id,
            usePurpose48: n > 1
        };
        this.request.post('/v2/wallets/', args, function (err, res) {
            if (err)
                return cb(err);
            var walletId = res.walletId;
            c.addWalletInfo(walletId, walletName, m, n, copayerName);
            var secret = API._buildSecret(c.walletId, c.walletPrivKey, c.coin, c.network);
            _this._doJoinWallet(walletId, walletPrivKey, c.xPubKey, c.requestPubKey, copayerName, {
                coin: coin
            }, function (err, wallet) {
                if (err)
                    return cb(err);
                return cb(null, n > 1 ? secret : null);
            });
        });
    };
    API.prototype.joinWallet = function (secret, copayerName, opts, cb) {
        var _this = this;
        if (!cb) {
            cb = opts;
            opts = {};
            log.warn('DEPRECATED WARN: joinWallet should receive 4 parameters.');
        }
        if (!this._checkKeyDerivation())
            return cb(new Error('Cannot join wallet'));
        opts = opts || {};
        var coin = opts.coin || 'btc';
        if (!lodash_1.default.includes(common_1.Constants.COINS, coin))
            return cb(new Error('Invalid coin'));
        try {
            var secretData = API.parseSecret(secret);
        }
        catch (ex) {
            return cb(ex);
        }
        if (!this.credentials) {
            return cb(new Error('Import credentials first with setCredentials()'));
        }
        this.credentials.addWalletPrivateKey(secretData.walletPrivKey.toString());
        this._doJoinWallet(secretData.walletId, secretData.walletPrivKey, this.credentials.xPubKey, this.credentials.requestPubKey, copayerName, {
            coin: coin,
            dryRun: !!opts.dryRun
        }, function (err, wallet) {
            if (err)
                return cb(err);
            if (!opts.dryRun) {
                _this.credentials.addWalletInfo(wallet.id, wallet.name, wallet.m, wallet.n, copayerName, { allowOverwrite: true });
            }
            return cb(null, wallet);
        });
    };
    API.prototype.recreateWallet = function (cb) {
        var _this = this;
        $.checkState(this.credentials);
        $.checkState(this.credentials.isComplete());
        $.checkState(this.credentials.walletPrivKey);
        this.getStatus({
            includeExtendedInfo: true
        }, function (err) {
            if (!err) {
                log.info('Wallet is already created');
                return cb();
            }
            var c = _this.credentials;
            var walletPrivKey = Bitcore.PrivateKey.fromString(c.walletPrivKey);
            var walletId = c.walletId;
            var supportBIP44AndP2PKH = c.derivationStrategy != common_1.Constants.DERIVATION_STRATEGIES.BIP45;
            var encWalletName = common_1.Utils.encryptMessage(c.walletName || 'recovered wallet', c.sharedEncryptingKey);
            var coin = c.coin;
            var args = {
                name: encWalletName,
                m: c.m,
                n: c.n,
                pubKey: walletPrivKey.toPublicKey().toString(),
                coin: c.coin,
                network: c.network,
                id: walletId,
                supportBIP44AndP2PKH: supportBIP44AndP2PKH
            };
            _this.request.post('/v2/wallets/', args, function (err, body) {
                if (err) {
                    log.info('openWallet error' + err);
                    return cb(new Errors.WALLET_DOES_NOT_EXIST());
                }
                if (!walletId) {
                    walletId = body.walletId;
                }
                var i = 1;
                async.each(_this.credentials.publicKeyRing, function (item, next) {
                    var name = item.copayerName || 'copayer ' + i++;
                    _this._doJoinWallet(walletId, walletPrivKey, item.xPubKey, item.requestPubKey, name, {
                        coin: c.coin,
                        supportBIP44AndP2PKH: supportBIP44AndP2PKH
                    }, function (err) {
                        if (err && err instanceof Errors.COPAYER_IN_WALLET)
                            return next();
                        return next(err);
                    });
                }, cb);
            });
        });
    };
    API.prototype._processWallet = function (wallet) {
        var encryptingKey = this.credentials.sharedEncryptingKey;
        var name = common_1.Utils.decryptMessageNoThrow(wallet.name, encryptingKey);
        if (name != wallet.name) {
            wallet.encryptedName = wallet.name;
        }
        wallet.name = name;
        lodash_1.default.each(wallet.copayers, function (copayer) {
            var name = common_1.Utils.decryptMessageNoThrow(copayer.name, encryptingKey);
            if (name != copayer.name) {
                copayer.encryptedName = copayer.name;
            }
            copayer.name = name;
            lodash_1.default.each(copayer.requestPubKeys, function (access) {
                if (!access.name)
                    return;
                var name = common_1.Utils.decryptMessageNoThrow(access.name, encryptingKey);
                if (name != access.name) {
                    access.encryptedName = access.name;
                }
                access.name = name;
            });
        });
    };
    API.prototype._processStatus = function (status) {
        var _this = this;
        var processCustomData = function (data) {
            var copayers = data.wallet.copayers;
            if (!copayers)
                return;
            var me = lodash_1.default.find(copayers, {
                id: _this.credentials.copayerId
            });
            if (!me || !me.customData)
                return;
            var customData;
            try {
                customData = JSON.parse(common_1.Utils.decryptMessage(me.customData, _this.credentials.personalEncryptingKey));
            }
            catch (e) {
                log.warn('Could not decrypt customData:', me.customData);
            }
            if (!customData)
                return;
            data.customData = customData;
            if (!_this.credentials.walletPrivKey && customData.walletPrivKey)
                _this.credentials.addWalletPrivateKey(customData.walletPrivKey);
        };
        processCustomData(status);
        this._processWallet(status.wallet);
        this._processTxps(status.pendingTxps);
    };
    API.prototype.getNotifications = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials);
        opts = opts || {};
        var url = '/v1/notifications/';
        if (opts.lastNotificationId) {
            url += '?notificationId=' + opts.lastNotificationId;
        }
        else if (opts.timeSpan) {
            url += '?timeSpan=' + opts.timeSpan;
        }
        this.request.getWithLogin(url, function (err, result) {
            if (err)
                return cb(err);
            var notifications = lodash_1.default.filter(result, function (notification) {
                return (opts.includeOwn ||
                    notification.creatorId != _this.credentials.copayerId);
            });
            return cb(null, notifications);
        });
    };
    API.prototype.getStatus = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials);
        if (!cb) {
            cb = opts;
            opts = {};
            log.warn('DEPRECATED WARN: getStatus should receive 2 parameters.');
        }
        opts = opts || {};
        var qs = [];
        qs.push('includeExtendedInfo=' + (opts.includeExtendedInfo ? '1' : '0'));
        qs.push('twoStep=' + (opts.twoStep ? '1' : '0'));
        qs.push('serverMessageArray=1');
        this.request.get('/v3/wallets/?' + qs.join('&'), function (err, result) {
            if (err)
                return cb(err);
            if (result.wallet.status == 'pending') {
                var c = _this.credentials;
                result.wallet.secret = API._buildSecret(c.walletId, c.walletPrivKey, c.coin, c.network);
            }
            _this._processStatus(result);
            return cb(err, result);
        });
    };
    API.prototype.getPreferences = function (cb) {
        $.checkState(this.credentials);
        $.checkArgument(cb);
        this.request.get('/v1/preferences/', function (err, preferences) {
            if (err)
                return cb(err);
            return cb(null, preferences);
        });
    };
    API.prototype.savePreferences = function (preferences, cb) {
        $.checkState(this.credentials);
        $.checkArgument(cb);
        this.request.put('/v1/preferences/', preferences, cb);
    };
    API.prototype.fetchPayPro = function (opts, cb) {
        $.checkArgument(opts).checkArgument(opts.payProUrl);
        paypro_1.PayPro.get({
            url: opts.payProUrl,
            coin: this.credentials.coin || 'btc',
            network: this.credentials.network || 'livenet',
            request: this.request
        }, function (err, paypro) {
            if (err)
                return cb(err);
            return cb(null, paypro);
        });
    };
    API.prototype.getUtxos = function (opts, cb) {
        $.checkState(this.credentials && this.credentials.isComplete());
        opts = opts || {};
        var url = '/v1/utxos/';
        if (opts.addresses) {
            url +=
                '?' +
                    querystring.stringify({
                        addresses: [].concat(opts.addresses).join(',')
                    });
        }
        this.request.get(url, cb);
    };
    API.prototype._getCreateTxProposalArgs = function (opts) {
        var _this = this;
        var args = lodash_1.default.cloneDeep(opts);
        args.message =
            API._encryptMessage(opts.message, this.credentials.sharedEncryptingKey) ||
                null;
        args.payProUrl = opts.payProUrl || null;
        lodash_1.default.each(args.outputs, function (o) {
            o.message =
                API._encryptMessage(o.message, _this.credentials.sharedEncryptingKey) ||
                    null;
        });
        return args;
    };
    API.prototype.createTxProposal = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        $.checkState(this.credentials.sharedEncryptingKey);
        $.checkArgument(opts);
        var args = this._getCreateTxProposalArgs(opts);
        this.request.post('/v3/txproposals/', args, function (err, txp) {
            if (err)
                return cb(err);
            _this._processTxps(txp);
            if (!verifier_1.Verifier.checkProposalCreation(args, txp, _this.credentials.sharedEncryptingKey)) {
                return cb(new Errors.SERVER_COMPROMISED());
            }
            return cb(null, txp);
        });
    };
    API.prototype.publishTxProposal = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        $.checkArgument(opts).checkArgument(opts.txp);
        $.checkState(parseInt(opts.txp.version) >= 3);
        var t = common_1.Utils.buildTx(opts.txp);
        var hash = t.uncheckedSerialize();
        var args = {
            proposalSignature: common_1.Utils.signMessage(hash, this.credentials.requestPrivKey)
        };
        var url = '/v2/txproposals/' + opts.txp.id + '/publish/';
        this.request.post(url, args, function (err, txp) {
            if (err)
                return cb(err);
            _this._processTxps(txp);
            return cb(null, txp);
        });
    };
    API.prototype.createAddress = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        if (!cb) {
            cb = opts;
            opts = {};
            log.warn('DEPRECATED WARN: createAddress should receive 2 parameters.');
        }
        if (!this._checkKeyDerivation())
            return cb(new Error('Cannot create new address for this wallet'));
        opts = opts || {};
        this.request.post('/v4/addresses/', opts, function (err, address) {
            if (err)
                return cb(err);
            if (!verifier_1.Verifier.checkAddress(_this.credentials, address)) {
                return cb(new Errors.SERVER_COMPROMISED());
            }
            return cb(null, address);
        });
    };
    API.prototype.getMainAddresses = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        opts = opts || {};
        var args = [];
        if (opts.limit)
            args.push('limit=' + opts.limit);
        if (opts.reverse)
            args.push('reverse=1');
        var qs = '';
        if (args.length > 0) {
            qs = '?' + args.join('&');
        }
        var url = '/v1/addresses/' + qs;
        this.request.get(url, function (err, addresses) {
            if (err)
                return cb(err);
            if (!opts.doNotVerify) {
                var fake = lodash_1.default.some(addresses, function (address) {
                    return !verifier_1.Verifier.checkAddress(_this.credentials, address);
                });
                if (fake)
                    return cb(new Errors.SERVER_COMPROMISED());
            }
            return cb(null, addresses);
        });
    };
    API.prototype.getBalance = function (opts, cb) {
        if (!cb) {
            cb = opts;
            opts = {};
            log.warn('DEPRECATED WARN: getBalance should receive 2 parameters.');
        }
        opts = opts || {};
        $.checkState(this.credentials && this.credentials.isComplete());
        var args = [];
        if (opts.coin) {
            if (!lodash_1.default.includes(common_1.Constants.COINS, opts.coin))
                return cb(new Error('Invalid coin'));
            args.push('coin=' + opts.coin);
        }
        var qs = '';
        if (args.length > 0) {
            qs = '?' + args.join('&');
        }
        var url = '/v1/balance/' + qs;
        this.request.get(url, cb);
    };
    API.prototype.getTxProposals = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        this.request.get('/v2/txproposals/', function (err, txps) {
            if (err)
                return cb(err);
            _this._processTxps(txps);
            async.every(txps, function (txp, acb) {
                if (opts.doNotVerify)
                    return acb(true);
                _this.getPayPro(txp, function (err, paypro) {
                    var isLegit = verifier_1.Verifier.checkTxProposal(_this.credentials, txp, {
                        paypro: paypro
                    });
                    return acb(isLegit);
                });
            }, function (isLegit) {
                if (!isLegit)
                    return cb(new Errors.SERVER_COMPROMISED());
                var result;
                if (opts.forAirGapped) {
                    result = {
                        txps: JSON.parse(JSON.stringify(txps)),
                        encryptedPkr: opts.doNotEncryptPkr
                            ? null
                            : common_1.Utils.encryptMessage(JSON.stringify(_this.credentials.publicKeyRing), _this.credentials.personalEncryptingKey),
                        unencryptedPkr: opts.doNotEncryptPkr
                            ? JSON.stringify(_this.credentials.publicKeyRing)
                            : null,
                        m: _this.credentials.m,
                        n: _this.credentials.n
                    };
                }
                else {
                    result = txps;
                }
                return cb(null, result);
            });
        });
    };
    API.prototype.getPayPro = function (txp, cb) {
        if (!txp.payProUrl || this.doNotVerifyPayPro)
            return cb();
        paypro_1.PayPro.get({
            url: txp.payProUrl,
            coin: txp.coin || 'btc',
            network: txp.network || 'livenet',
            request: this.request
        }, function (err, paypro) {
            if (err)
                return cb(new Error('Could not fetch invoice:' + (err.message ? err.message : err)));
            return cb(null, paypro);
        });
    };
    API.prototype.pushSignatures = function (txp, signatures, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        $.checkArgument(txp.creatorId);
        if (lodash_1.default.isEmpty(signatures)) {
            return cb('No signatures to push. Sign the transaction with Key first');
        }
        this.getPayPro(txp, function (err, paypro) {
            if (err)
                return cb(err);
            var isLegit = verifier_1.Verifier.checkTxProposal(_this.credentials, txp, {
                paypro: paypro
            });
            if (!isLegit)
                return cb(new Errors.SERVER_COMPROMISED());
            var url = '/v1/txproposals/' + txp.id + '/signatures/';
            var args = {
                signatures: signatures
            };
            _this.request.post(url, args, function (err, txp) {
                if (err)
                    return cb(err);
                _this._processTxps(txp);
                return cb(null, txp);
            });
        });
    };
    API.prototype.signTxProposalFromAirGapped = function (txp, encryptedPkr, m, n, password) {
        throw new Error('signTxProposalFromAirGapped not yet implemented in v9.0.0');
    };
    API.signTxProposalFromAirGapped = function (key, txp, unencryptedPkr, m, n, opts, cb) {
        opts = opts || {};
        var coin = opts.coin || 'btc';
        if (!lodash_1.default.includes(common_1.Constants.COINS, coin))
            return cb(new Error('Invalid coin'));
        var publicKeyRing = JSON.parse(unencryptedPkr);
        if (!lodash_1.default.isArray(publicKeyRing) || publicKeyRing.length != n) {
            throw new Error('Invalid public key ring');
        }
        var newClient = new API({
            baseUrl: 'https://bws.example.com/bws/api'
        });
        if (key.slice(0, 4) === 'xprv' || key.slice(0, 4) === 'tprv') {
            if (key.slice(0, 4) === 'xprv' && txp.network == 'testnet')
                throw new Error('testnet HD keys must start with tprv');
            if (key.slice(0, 4) === 'tprv' && txp.network == 'livenet')
                throw new Error('livenet HD keys must start with xprv');
            newClient.seedFromExtendedPrivateKey(key, {
                coin: coin,
                account: opts.account,
                derivationStrategy: opts.derivationStrategy
            });
        }
        else {
            newClient.seedFromMnemonic(key, {
                coin: coin,
                network: txp.network,
                passphrase: opts.passphrase,
                account: opts.account,
                derivationStrategy: opts.derivationStrategy
            });
        }
        newClient.credentials.m = m;
        newClient.credentials.n = n;
        newClient.credentials.addressType = txp.addressType;
        newClient.credentials.addPublicKeyRing(publicKeyRing);
        if (!verifier_1.Verifier.checkTxProposalSignature(newClient.credentials, txp))
            throw new Error('Fake transaction proposal');
        return newClient._signTxp(txp);
    };
    API.prototype.rejectTxProposal = function (txp, reason, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        $.checkArgument(cb);
        var url = '/v1/txproposals/' + txp.id + '/rejections/';
        var args = {
            reason: API._encryptMessage(reason, this.credentials.sharedEncryptingKey) || ''
        };
        this.request.post(url, args, function (err, txp) {
            if (err)
                return cb(err);
            _this._processTxps(txp);
            return cb(null, txp);
        });
    };
    API.prototype.broadcastRawTx = function (opts, cb) {
        $.checkState(this.credentials);
        $.checkArgument(cb);
        opts = opts || {};
        var url = '/v1/broadcast_raw/';
        this.request.post(url, opts, function (err, txid) {
            if (err)
                return cb(err);
            return cb(null, txid);
        });
    };
    API.prototype._doBroadcast = function (txp, cb) {
        var _this = this;
        var url = '/v1/txproposals/' + txp.id + '/broadcast/';
        this.request.post(url, {}, function (err, txp) {
            if (err)
                return cb(err);
            _this._processTxps(txp);
            return cb(null, txp);
        });
    };
    API.prototype.broadcastTxProposal = function (txp, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        this.getPayPro(txp, function (err, paypro) {
            if (err)
                return cb(err);
            if (paypro) {
                var t_unsigned = common_1.Utils.buildTx(txp);
                var t = common_1.Utils.buildTx(txp);
                _this._applyAllSignatures(txp, t);
                paypro_1.PayPro.send({
                    url: txp.payProUrl,
                    amountSat: txp.amount,
                    rawTxUnsigned: t_unsigned.uncheckedSerialize(),
                    rawTx: t.serialize({
                        disableSmallFees: true,
                        disableLargeFees: true,
                        disableDustOutputs: true
                    }),
                    coin: txp.coin || 'btc',
                    network: txp.network || 'livenet',
                    bp_partner: _this.bp_partner,
                    bp_partner_version: _this.bp_partner_version,
                    request: _this.request
                }, function (err, ack, memo) {
                    if (err) {
                        return cb(err);
                    }
                    if (memo) {
                        log.debug('Merchant memo:', memo);
                    }
                    _this._doBroadcast(txp, function (err2, txp) {
                        if (err2) {
                            log.error('Error broadcasting payment', err2);
                        }
                        return cb(null, txp, memo);
                    });
                });
            }
            else {
                _this._doBroadcast(txp, cb);
            }
        });
    };
    API.prototype.removeTxProposal = function (txp, cb) {
        $.checkState(this.credentials && this.credentials.isComplete());
        var url = '/v1/txproposals/' + txp.id;
        this.request.delete(url, function (err) {
            return cb(err);
        });
    };
    API.prototype.getTxHistory = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        var args = [];
        if (opts) {
            if (opts.skip)
                args.push('skip=' + opts.skip);
            if (opts.limit)
                args.push('limit=' + opts.limit);
            if (opts.includeExtendedInfo)
                args.push('includeExtendedInfo=1');
        }
        var qs = '';
        if (args.length > 0) {
            qs = '?' + args.join('&');
        }
        var url = '/v1/txhistory/' + qs;
        this.request.get(url, function (err, txs) {
            if (err)
                return cb(err);
            _this._processTxps(txs);
            return cb(null, txs);
        });
    };
    API.prototype.getTx = function (id, cb) {
        var _this = this;
        $.checkState(this.credentials && this.credentials.isComplete());
        var url = '/v1/txproposals/' + id;
        this.request.get(url, function (err, txp) {
            if (err)
                return cb(err);
            _this._processTxps(txp);
            return cb(null, txp);
        });
    };
    API.prototype.startScan = function (opts, cb) {
        $.checkState(this.credentials && this.credentials.isComplete());
        var args = {
            includeCopayerBranches: opts.includeCopayerBranches
        };
        this.request.post('/v1/addresses/scan', args, function (err) {
            return cb(err);
        });
    };
    API.prototype.addAccess = function (opts, cb) {
        $.checkState(this.credentials);
        $.shouldBeString(opts.requestPrivKey, 'no requestPrivKey at addAccess() ');
        $.shouldBeString(opts.signature, 'no signature at addAccess()');
        opts = opts || {};
        var requestPubKey = new Bitcore.PrivateKey(opts.requestPrivKey)
            .toPublicKey()
            .toString();
        var copayerId = this.credentials.copayerId;
        var encCopayerName = opts.name
            ? common_1.Utils.encryptMessage(opts.name, this.credentials.sharedEncryptingKey)
            : null;
        var opts2 = {
            copayerId: copayerId,
            requestPubKey: requestPubKey,
            signature: opts.signature,
            name: encCopayerName,
            restrictions: opts.restrictions
        };
        this.request.put('/v1/copayers/' + copayerId + '/', opts2, function (err, res) {
            if (err)
                return cb(err);
            return cb(null, res.wallet, opts.requestPrivKey);
        });
    };
    API.prototype.getTxNote = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials);
        opts = opts || {};
        this.request.get('/v1/txnotes/' + opts.txid + '/', function (err, note) {
            if (err)
                return cb(err);
            _this._processTxNotes(note);
            return cb(null, note);
        });
    };
    API.prototype.editTxNote = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials);
        opts = opts || {};
        if (opts.body) {
            opts.body = API._encryptMessage(opts.body, this.credentials.sharedEncryptingKey);
        }
        this.request.put('/v1/txnotes/' + opts.txid + '/', opts, function (err, note) {
            if (err)
                return cb(err);
            _this._processTxNotes(note);
            return cb(null, note);
        });
    };
    API.prototype.getTxNotes = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials);
        opts = opts || {};
        var args = [];
        if (lodash_1.default.isNumber(opts.minTs)) {
            args.push('minTs=' + opts.minTs);
        }
        var qs = '';
        if (args.length > 0) {
            qs = '?' + args.join('&');
        }
        this.request.get('/v1/txnotes/' + qs, function (err, notes) {
            if (err)
                return cb(err);
            _this._processTxNotes(notes);
            return cb(null, notes);
        });
    };
    API.prototype.getFiatRate = function (opts, cb) {
        $.checkArgument(cb);
        var opts = opts || {};
        var args = [];
        if (opts.ts)
            args.push('ts=' + opts.ts);
        if (opts.coin)
            args.push('coin=' + opts.coin);
        var qs = '';
        if (args.length > 0) {
            qs = '?' + args.join('&');
        }
        this.request.get('/v1/fiatrates/' + opts.code + '/' + qs, function (err, rates) {
            if (err)
                return cb(err);
            return cb(null, rates);
        });
    };
    API.prototype.pushNotificationsSubscribe = function (opts, cb) {
        var url = '/v1/pushnotifications/subscriptions/';
        this.request.post(url, opts, function (err, response) {
            if (err)
                return cb(err);
            return cb(null, response);
        });
    };
    API.prototype.pushNotificationsUnsubscribe = function (token, cb) {
        var url = '/v2/pushnotifications/subscriptions/' + token;
        this.request.delete(url, cb);
    };
    API.prototype.txConfirmationSubscribe = function (opts, cb) {
        var url = '/v1/txconfirmations/';
        this.request.post(url, opts, function (err, response) {
            if (err)
                return cb(err);
            return cb(null, response);
        });
    };
    API.prototype.txConfirmationUnsubscribe = function (txid, cb) {
        var url = '/v1/txconfirmations/' + txid;
        this.request.delete(url, cb);
    };
    API.prototype.getSendMaxInfo = function (opts, cb) {
        var args = [];
        opts = opts || {};
        if (opts.feeLevel)
            args.push('feeLevel=' + opts.feeLevel);
        if (opts.feePerKb != null)
            args.push('feePerKb=' + opts.feePerKb);
        if (opts.excludeUnconfirmedUtxos)
            args.push('excludeUnconfirmedUtxos=1');
        if (opts.returnInputs)
            args.push('returnInputs=1');
        var qs = '';
        if (args.length > 0)
            qs = '?' + args.join('&');
        var url = '/v1/sendmaxinfo/' + qs;
        this.request.get(url, function (err, result) {
            if (err)
                return cb(err);
            return cb(null, result);
        });
    };
    API.prototype.getEstimateGas = function (opts, cb) {
        var url = '/v3/estimateGas/';
        this.request.post(url, opts, function (err, gasLimit) {
            if (err)
                return cb(err);
            return cb(null, gasLimit);
        });
    };
    API.prototype.getStatusByIdentifier = function (opts, cb) {
        var _this = this;
        $.checkState(this.credentials);
        opts = opts || {};
        var qs = [];
        qs.push('includeExtendedInfo=' + (opts.includeExtendedInfo ? '1' : '0'));
        qs.push('walletCheck=' + (opts.walletCheck ? '1' : '0'));
        this.request.get('/v1/wallets/' + opts.identifier + '?' + qs.join('&'), function (err, result) {
            if (err || !result || !result.wallet)
                return cb(err);
            if (result.wallet.status == 'pending') {
                var c = _this.credentials;
                result.wallet.secret = API._buildSecret(c.walletId, c.walletPrivKey, c.coin, c.network);
            }
            _this._processStatus(result);
            return cb(err, result);
        });
    };
    API.prototype._oldCopayDecrypt = function (username, password, blob) {
        var SEP1 = '@#$';
        var SEP2 = '%^#@';
        var decrypted;
        try {
            var passphrase = username + SEP1 + password;
            decrypted = sjcl_1.default.decrypt(passphrase, blob);
        }
        catch (e) {
            passphrase = username + SEP2 + password;
            try {
                decrypted = sjcl_1.default.decrypt(passphrase, blob);
            }
            catch (e) {
                log.debug(e);
            }
        }
        if (!decrypted)
            return null;
        var ret;
        try {
            ret = JSON.parse(decrypted);
        }
        catch (e) { }
        return ret;
    };
    API.prototype.getWalletIdsFromOldCopay = function (username, password, blob) {
        var p = this._oldCopayDecrypt(username, password, blob);
        if (!p)
            return null;
        var ids = p.walletIds.concat(lodash_1.default.keys(p.focusedTimestamps));
        return lodash_1.default.uniq(ids);
    };
    API.upgradeCredentialsV1 = function (x) {
        $.shouldBeObject(x);
        if (!lodash_1.default.isUndefined(x.version) ||
            (!x.xPrivKey && !x.xPrivKeyEncrypted && !x.xPubKey)) {
            throw new Error('Could not recognize old version');
        }
        var k;
        if (x.xPrivKey || x.xPrivKeyEncrypted) {
            k = new key_1.Key();
            lodash_1.default.each(key_1.Key.FIELDS, function (i) {
                if (!lodash_1.default.isUndefined(x[i])) {
                    k[i] = x[i];
                }
            });
            k.use44forMultisig = x.n > 1 ? true : false;
            k.use0forBCH = x.use145forBCH ? false : x.coin == 'bch' ? true : false;
            k.BIP45 = x.derivationStrategy == 'BIP45';
        }
        else {
            k = false;
        }
        var obsoleteFields = {
            version: true,
            xPrivKey: true,
            xPrivKeyEncrypted: true,
            hwInfo: true,
            entropySourcePath: true,
            mnemonic: true,
            mnemonicEncrypted: true
        };
        var c = new credentials_1.Credentials();
        lodash_1.default.each(credentials_1.Credentials.FIELDS, function (i) {
            if (!obsoleteFields[i]) {
                c[i] = x[i];
            }
        });
        if (c.externalSource) {
            throw new Error('External Wallets are no longer supported');
        }
        c.coin = c.coin || 'btc';
        c.addressType = c.addressType || common_1.Constants.SCRIPT_TYPES.P2SH;
        c.account = c.account || 0;
        c.rootPath = c.getRootPath();
        c.keyId = k.id;
        return { key: k, credentials: c };
    };
    API.upgradeMultipleCredentialsV1 = function (oldCredentials) {
        var newKeys = [], newCrededentials = [];
        lodash_1.default.each(oldCredentials, function (credentials) {
            var migrated;
            if (!credentials.version || credentials.version < 2) {
                log.info('About to migrate : ' + credentials.walletId);
                migrated = API.upgradeCredentialsV1(credentials);
                newCrededentials.push(migrated.credentials);
                if (migrated.key) {
                    log.info("Wallet " + credentials.walletId + " key's extracted");
                    newKeys.push(migrated.key);
                }
                else {
                    log.info("READ-ONLY Wallet " + credentials.walletId + " migrated");
                }
            }
        });
        if (newKeys.length > 0) {
            var credGroups = lodash_1.default.groupBy(newCrededentials, function (x) {
                $.checkState(x.xPubKey, 'no xPubKey at credentials!');
                var xpub = new Bitcore.HDPublicKey(x.xPubKey);
                var fingerPrint = xpub.fingerPrint.toString('hex');
                return fingerPrint;
            });
            if (lodash_1.default.keys(credGroups).length < newCrededentials.length) {
                log.info('Found some wallets using the SAME key. Merging...');
                var uniqIds_1 = {};
                lodash_1.default.each(lodash_1.default.values(credGroups), function (credList) {
                    var toKeep = credList.shift();
                    if (!toKeep.keyId)
                        return;
                    uniqIds_1[toKeep.keyId] = true;
                    if (!credList.length)
                        return;
                    log.info("Merging " + credList.length + " keys to " + toKeep.keyId);
                    lodash_1.default.each(credList, function (x) {
                        log.info("\t" + x.keyId + " is now " + toKeep.keyId);
                        x.keyId = toKeep.keyId;
                    });
                });
                newKeys = lodash_1.default.filter(newKeys, function (x) { return uniqIds_1[x.id]; });
            }
        }
        return {
            keys: newKeys,
            credentials: newCrededentials
        };
    };
    API.serverAssistedImport = function (opts, clientOpts, callback) {
        $.checkArgument(opts.words || opts.xPrivKey, 'provide opts.words or opts.xPrivKey');
        var copayerIdAlreadyTested = {};
        var checkCredentials = function (key, opts, icb) {
            var c = key.createCredentials(null, {
                coin: opts.coin,
                network: opts.network,
                account: opts.account,
                n: opts.n
            });
            if (copayerIdAlreadyTested[c.copayerId + ':' + opts.n]) {
                return icb();
            }
            else {
                copayerIdAlreadyTested[c.copayerId + ':' + opts.n] = true;
            }
            var client = clientOpts.clientFactory
                ? clientOpts.clientFactory()
                : new API(clientOpts);
            client.fromString(c);
            client.openWallet({}, function (err) {
                console.log("PATH: " + c.rootPath + " n: " + c.n + ":", err && err.message ? err.message : 'FOUND!');
                if (!err)
                    return icb(null, client);
                if (err instanceof Errors.NOT_AUTHORIZED ||
                    err instanceof Errors.WALLET_DOES_NOT_EXIST) {
                    return icb();
                }
                return icb(err);
            });
        };
        var checkKey = function (key, cb) {
            var opts = [
                ['btc', 'livenet'],
                ['bch', 'livenet'],
                ['eth', 'livenet'],
                ['eth', 'testnet'],
                ['btc', 'livenet', true],
                ['bch', 'livenet', true]
            ];
            if (key.use44forMultisig) {
                opts = opts.filter(function (x) {
                    return x[2];
                });
            }
            if (key.use0forBCH) {
                opts = opts.filter(function (x) {
                    return x[0] == 'bch';
                });
            }
            if (!key.nonCompliantDerivation) {
                var testnet = lodash_1.default.cloneDeep(opts);
                testnet.forEach(function (x) {
                    x[1] = 'testnet';
                });
                opts = opts.concat(testnet);
            }
            else {
                opts = opts.filter(function (x) {
                    return x[0] == 'btc';
                });
            }
            var clients = [];
            async.eachSeries(opts, function (x, next) {
                var optsObj = {
                    coin: x[0],
                    network: x[1],
                    account: 0,
                    n: x[2] ? 2 : 1
                };
                checkCredentials(key, optsObj, function (err, iclient) {
                    if (err)
                        return next(err);
                    if (!iclient)
                        return next();
                    clients.push(iclient);
                    if (key.use0forBCH ||
                        !key.compliantDerivation ||
                        key.use44forMultisig ||
                        key.BIP45)
                        return next();
                    var cont = true, account = 1;
                    async.whilst(function () {
                        return cont;
                    }, function (icb) {
                        optsObj.account = account++;
                        checkCredentials(key, optsObj, function (err, iclient) {
                            if (err)
                                return icb(err);
                            cont = !!iclient;
                            if (iclient) {
                                clients.push(iclient);
                            }
                            else {
                                cont = false;
                            }
                            return icb();
                        });
                    }, function (err) {
                        return next(err);
                    });
                });
            }, function (err) {
                if (err)
                    return cb(err);
                return cb(null, clients);
            });
        };
        var sets = [
            {
                nonCompliantDerivation: false,
                useLegacyCoinType: false,
                useLegacyPurpose: false
            },
            {
                nonCompliantDerivation: false,
                useLegacyCoinType: true,
                useLegacyPurpose: false
            },
            {
                nonCompliantDerivation: false,
                useLegacyCoinType: false,
                useLegacyPurpose: true
            },
            {
                nonCompliantDerivation: false,
                useLegacyCoinType: true,
                useLegacyPurpose: true
            },
            {
                nonCompliantDerivation: true,
                useLegacyPurpose: true
            }
        ];
        var s, resultingClients = [], k;
        async.whilst(function () {
            if (!lodash_1.default.isEmpty(resultingClients))
                return false;
            s = sets.shift();
            if (!s)
                return false;
            try {
                if (opts.words) {
                    if (opts.passphrase) {
                        s.passphrase = opts.passphrase;
                    }
                    k = key_1.Key.fromMnemonic(opts.words, s);
                }
                else {
                    k = key_1.Key.fromExtendedPrivateKey(opts.xPrivKey, s);
                }
            }
            catch (e) {
                log.info('Backup error:', e);
                return callback(new Errors.INVALID_BACKUP());
            }
            return true;
        }, function (icb) {
            checkKey(k, function (err, clients) {
                if (err)
                    return icb(err);
                if (clients && clients.length) {
                    resultingClients = clients;
                }
                return icb();
            });
        }, function (err) {
            if (err)
                return callback(err);
            if (lodash_1.default.isEmpty(resultingClients))
                k = null;
            return callback(null, k, resultingClients);
        });
    };
    API.PayPro = paypro_1.PayPro;
    API.Key = key_1.Key;
    API.Verifier = verifier_1.Verifier;
    API.Core = CWC;
    API.Utils = common_1.Utils;
    API.sjcl = sjcl_1.default;
    API.errors = Errors;
    API.Bitcore = require('bitcore-lib');
    API.BitcoreCash = require('bitcore-lib-cash');
    API.privateKeyEncryptionOpts = {
        iter: 10000
    };
    return API;
}(events_1.EventEmitter));
exports.API = API;
//# sourceMappingURL=api.js.map