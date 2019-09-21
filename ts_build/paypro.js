"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var $ = require('preconditions').singleton();
var URL = require('url');
var _ = require('lodash');
var superagent = require('superagent');
var Bitcore = require('bitcore-lib');
var Errors = require('./errors');
var Bitcore_ = {
    btc: Bitcore,
    bch: require('bitcore-lib-cash')
};
var JSON_PAYMENT_REQUEST_CONTENT_TYPE = 'application/payment-request';
var JSON_PAYMENT_VERIFY_CONTENT_TYPE = 'application/verify-payment';
var JSON_PAYMENT_CONTENT_TYPE = 'application/payment';
var JSON_PAYMENT_ACK_CONTENT_TYPE = 'application/payment-ack';
var dfltTrustedKeys = require('../util/JsonPaymentProtocolKeys.js');
var MAX_FEE_PER_KB = 500000;
var PayPro = (function () {
    function PayPro() {
    }
    PayPro._verify = function (requestUrl, headers, network, trustedKeys, callback) {
        var hash = headers.digest.split('=')[1];
        var signature = headers.signature;
        var signatureType = headers['x-signature-type'];
        var identity = headers['x-identity'];
        var host;
        if (network == 'testnet')
            network = 'test';
        if (network == 'livenet')
            network = 'main';
        if (!requestUrl) {
            return callback(new Error('You must provide the original payment request url'));
        }
        if (!trustedKeys) {
            return callback(new Error('You must provide a set of trusted keys'));
        }
        try {
            host = URL.parse(requestUrl).hostname;
        }
        catch (e) { }
        if (!host) {
            return callback(new Error('Invalid requestUrl'));
        }
        if (!signatureType) {
            return callback(new Error('Response missing x-signature-type header'));
        }
        if (typeof signatureType !== 'string') {
            return callback(new Error('Invalid x-signature-type header'));
        }
        if (signatureType !== 'ecc') {
            return callback(new Error("Unknown signature type " + signatureType));
        }
        if (!signature) {
            return callback(new Error('Response missing signature header'));
        }
        if (typeof signature !== 'string') {
            return callback(new Error('Invalid signature header'));
        }
        if (!identity) {
            return callback(new Error('Response missing x-identity header'));
        }
        if (typeof identity !== 'string') {
            return callback(new Error('Invalid identity header'));
        }
        if (!trustedKeys[identity]) {
            return callback(new Error("Response signed by unknown key (" + identity + "), unable to validate"));
        }
        var keyData = trustedKeys[identity];
        if (keyData.domains.indexOf(host) === -1) {
            return callback(new Error("The key on the response (" + identity + ") is not trusted for domain " + host));
        }
        else if (!keyData.networks.includes(network)) {
            return callback(new Error("The key on the response is not trusted for transactions on the '" + network + "' network"));
        }
        var hashbuf = Buffer.from(hash, 'hex');
        var sigbuf = Buffer.from(signature, 'hex');
        var s_r = Buffer.alloc(32);
        var s_s = Buffer.alloc(32);
        sigbuf.copy(s_r, 0, 0);
        sigbuf.copy(s_s, 0, 32);
        var s_rBN = Bitcore.crypto.BN.fromBuffer(s_r);
        var s_sBN = Bitcore.crypto.BN.fromBuffer(s_s);
        var pub = Bitcore.PublicKey.fromString(keyData.publicKey);
        var sig = new Bitcore.crypto.Signature();
        sig.set({ r: s_rBN, s: s_sBN });
        var valid = Bitcore.crypto.ECDSA.verify(hashbuf, sig, pub);
        if (!valid) {
            return callback(new Error('Response signature invalid'));
        }
        return callback(null, keyData.owner);
    };
    PayPro.runRequest = function (opts, cb) {
        $.checkArgument(opts.network, 'should pass network');
        var r = this.r[opts.method.toLowerCase()](opts.url);
        _.each(opts.headers, function (v, k) {
            if (v)
                r.set(k, v);
        });
        if (opts.args) {
            if (opts.method.toLowerCase() == 'post' || opts.method.toLowerCase() == 'put') {
                r.send(opts.args);
            }
            else {
                r.query(opts.args);
            }
        }
        r.end(function (err, res) {
            if (err)
                return cb(err);
            var body = res.text;
            if (!res || res.statusCode != 200) {
                if (res.statusCode == 400) {
                    return cb(new Errors.INVOICE_EXPIRED);
                }
                else if (res.statusCode == 404) {
                    return cb(new Errors.INVOICE_NOT_AVAILABLE);
                }
                else if (res.statusCode == 422) {
                    return cb(new Errors.UNCONFIRMED_INPUTS_NOT_ACCEPTED);
                }
                var m = res ? res.statusMessage || res.statusCode : '';
                return cb(new Error('Could not fetch invoice: ' + m));
            }
            if (opts.noVerify)
                return cb(null, body);
            if (!res.headers.digest) {
                return cb(new Error('Digest missing from response headers'));
            }
            var digest = res.headers.digest.toString().split('=')[1];
            var hash = Bitcore.crypto.Hash.sha256(Buffer.from(body, 'utf8')).toString('hex');
            if (digest !== hash) {
                return cb(new Error("Response body hash does not match digest header. Actual: " + hash + " Expected: " + digest));
            }
            PayPro._verify(opts.url, res.headers, opts.network, opts.trustedKeys, function (err) {
                if (err)
                    return cb(err);
                var ret;
                try {
                    ret = JSON.parse(body);
                }
                catch (e) {
                    return cb(new Error('Could not payment request:' + body));
                }
                ret.verified = 1;
                return cb(null, ret);
            });
        });
    };
    PayPro.get = function (opts, cb) {
        $.checkArgument(opts && opts.url);
        opts.trustedKeys = opts.trustedKeys || dfltTrustedKeys;
        var coin = opts.coin || 'btc';
        var bitcore = Bitcore_[coin];
        var COIN = coin.toUpperCase();
        opts.headers = opts.headers || {
            'Accept': JSON_PAYMENT_REQUEST_CONTENT_TYPE,
            'Content-Type': 'application/octet-stream'
        };
        opts.method = 'GET';
        opts.network = opts.network || 'livenet';
        PayPro.runRequest(opts, function (err, data) {
            if (err)
                return cb(err);
            var ret = {};
            ret.verified = true;
            if (data.network == 'test')
                ret.network = 'testnet';
            if (data.network == 'main')
                ret.network = 'livenet';
            if (!data.network)
                return cb(new Error('No network at payment request'));
            if (data.currency != COIN)
                return cb(new Error('Currency mismatch. Expecting:' + COIN));
            ret.coin = coin;
            if (data.requiredFeeRate > MAX_FEE_PER_KB)
                return cb(new Error('Fee rate too high:' + data.requiredFeeRate));
            ret.requiredFeeRate = data.requiredFeeRate;
            if (!data.outputs || data.outputs.length != 1) {
                return cb(new Error('Must have 1 output'));
            }
            if (!_.isNumber(data.outputs[0].amount)) {
                return cb(new Error('Bad output amount'));
            }
            ret.amount = data.outputs[0].amount;
            try {
                ret.toAddress = new bitcore.Address(data.outputs[0].address).toString(true);
            }
            catch (e) {
                return cb(new Error('Bad output address ' + e));
            }
            ret.memo = data.memo;
            ret.paymentId = data.paymentId;
            try {
                ret.expires = new Date(data.expires).toISOString();
            }
            catch (e) {
                return cb(new Error('Bad expiration'));
            }
            return cb(null, ret);
        });
    };
    PayPro.send = function (opts, cb) {
        $.checkArgument(opts.rawTxUnsigned)
            .checkArgument(opts.url)
            .checkArgument(opts.rawTx);
        var coin = opts.coin || 'btc';
        var COIN = coin.toUpperCase();
        opts.network = opts.network || 'livenet';
        opts.method = 'POST';
        opts.headers = opts.headers || {
            'Content-Type': JSON_PAYMENT_VERIFY_CONTENT_TYPE
        };
        var size = opts.rawTx.length / 2;
        opts.args = JSON.stringify({
            currency: COIN,
            unsignedTransaction: opts.rawTxUnsigned,
            weightedSize: size
        });
        opts.noVerify = true;
        PayPro.runRequest(opts, function (err, rawData) {
            if (err) {
                console.log('Error at verify-payment:', err.message ? err.message : '', opts);
                return cb(err);
            }
            opts.headers = {
                'Content-Type': JSON_PAYMENT_CONTENT_TYPE,
                'Accept': JSON_PAYMENT_ACK_CONTENT_TYPE
            };
            if (opts.bp_partner) {
                opts.headers['BP_PARTNER'] = opts.bp_partner;
                if (opts.bp_partner_version) {
                    opts.headers['BP_PARTNER_VERSION'] = opts.bp_partner_version;
                }
            }
            opts.args = JSON.stringify({
                currency: COIN,
                transactions: [opts.rawTx]
            });
            opts.noVerify = true;
            PayPro.runRequest(opts, function (err, rawData) {
                if (err) {
                    console.log('Error at payment:', err.message ? err.message : '', opts);
                    return cb(err);
                }
                var memo;
                if (rawData) {
                    try {
                        var data = JSON.parse(rawData.toString());
                        memo = data.memo;
                    }
                    catch (e) {
                        console.log('Could not decode paymentACK');
                    }
                }
                return cb(null, rawData, memo);
            });
        });
    };
    PayPro.r = superagent;
    return PayPro;
}());
exports.PayPro = PayPro;
//# sourceMappingURL=paypro.js.map