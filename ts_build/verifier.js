"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var _ = __importStar(require("lodash"));
var common_1 = require("./common");
var $ = require('preconditions').singleton();
var Bitcore = require('bitcore-lib');
var BCHAddress = require('bitcore-lib-cash').Address;
var log = require('./log');
var Verifier = (function () {
    function Verifier() {
    }
    Verifier.checkAddress = function (credentials, address) {
        $.checkState(credentials.isComplete());
        var local = common_1.Utils.deriveAddress(address.type || credentials.addressType, credentials.publicKeyRing, address.path, credentials.m, credentials.network, credentials.coin);
        return (local.address == address.address &&
            _.difference(local.publicKeys, address.publicKeys).length === 0);
    };
    Verifier.checkCopayers = function (credentials, copayers) {
        $.checkState(credentials.walletPrivKey);
        var walletPubKey = Bitcore.PrivateKey.fromString(credentials.walletPrivKey).toPublicKey().toString();
        if (copayers.length != credentials.n) {
            log.error('Missing public keys in server response');
            return false;
        }
        var uniq = [];
        var error;
        _.each(copayers, function (copayer) {
            if (error)
                return;
            if (uniq[copayers.xPubKey]++) {
                log.error('Repeated public keys in server response');
                error = true;
            }
            if (!(copayer.encryptedName || copayer.name) || !copayer.xPubKey || !copayer.requestPubKey || !copayer.signature) {
                log.error('Missing copayer fields in server response');
                error = true;
            }
            else {
                var hash = common_1.Utils.getCopayerHash(copayer.encryptedName || copayer.name, copayer.xPubKey, copayer.requestPubKey);
                if (!common_1.Utils.verifyMessage(hash, copayer.signature, walletPubKey)) {
                    log.error('Invalid signatures in server response');
                    error = true;
                }
            }
        });
        if (error)
            return false;
        if (!_.includes(_.map(copayers, 'xPubKey'), credentials.xPubKey)) {
            log.error('Server response does not contains our public keys');
            return false;
        }
        return true;
    };
    Verifier.checkProposalCreation = function (args, txp, encryptingKey) {
        var strEqual = function (str1, str2) {
            return ((!str1 && !str2) || (str1 === str2));
        };
        if (txp.outputs.length != args.outputs.length)
            return false;
        for (var i = 0; i < txp.outputs.length; i++) {
            var o1 = txp.outputs[i];
            var o2 = args.outputs[i];
            if (!strEqual(o1.toAddress, o2.toAddress))
                return false;
            if (!strEqual(o1.script, o2.script))
                return false;
            if (o1.amount != o2.amount)
                return false;
            var decryptedMessage = null;
            try {
                decryptedMessage = common_1.Utils.decryptMessage(o2.message, encryptingKey);
            }
            catch (e) {
                return false;
            }
            if (!strEqual(o1.message, decryptedMessage))
                return false;
        }
        var changeAddress;
        if (txp.changeAddress) {
            changeAddress = txp.changeAddress.address;
        }
        if (args.changeAddress && !strEqual(changeAddress, args.changeAddress))
            return false;
        if (_.isNumber(args.feePerKb) && (txp.feePerKb != args.feePerKb))
            return false;
        if (!strEqual(txp.payProUrl, args.payProUrl))
            return false;
        var decryptedMessage = null;
        try {
            decryptedMessage = common_1.Utils.decryptMessage(args.message, encryptingKey);
        }
        catch (e) {
            return false;
        }
        if (!strEqual(txp.message, decryptedMessage))
            return false;
        if ((args.customData || txp.customData) && !_.isEqual(txp.customData, args.customData))
            return false;
        return true;
    };
    Verifier.checkTxProposalSignature = function (credentials, txp) {
        $.checkArgument(txp.creatorId);
        $.checkState(credentials.isComplete());
        var creatorKeys = _.find(credentials.publicKeyRing, function (item) {
            if (common_1.Utils.xPubToCopayerId(txp.coin || 'btc', item.xPubKey) === txp.creatorId)
                return true;
        });
        if (!creatorKeys)
            return false;
        var creatorSigningPubKey;
        if (txp.proposalSignaturePubKey) {
            if (!common_1.Utils.verifyRequestPubKey(txp.proposalSignaturePubKey, txp.proposalSignaturePubKeySig, creatorKeys.xPubKey))
                return false;
            creatorSigningPubKey = txp.proposalSignaturePubKey;
        }
        else {
            creatorSigningPubKey = creatorKeys.requestPubKey;
        }
        if (!creatorSigningPubKey)
            return false;
        var hash;
        if (parseInt(txp.version) >= 3) {
            var t = common_1.Utils.buildTx(txp);
            hash = t.uncheckedSerialize();
        }
        else {
            throw new Error('Transaction proposal not supported');
        }
        log.debug('Regenerating & verifying tx proposal hash -> Hash: ', hash, ' Signature: ', txp.proposalSignature);
        if (!common_1.Utils.verifyMessage(hash, txp.proposalSignature, creatorSigningPubKey))
            return false;
        if (!this.checkAddress(credentials, txp.changeAddress))
            return false;
        return true;
    };
    Verifier.checkPaypro = function (txp, payproOpts) {
        var toAddress, amount, feeRate;
        if (parseInt(txp.version) >= 3) {
            toAddress = txp.outputs[0].toAddress;
            amount = txp.amount;
            if (txp.feePerKb) {
                feeRate = txp.feePerKb / 1024;
            }
        }
        else {
            toAddress = txp.toAddress;
            amount = txp.amount;
        }
        if (amount != payproOpts.amount)
            return false;
        if (txp.coin == 'btc' && toAddress != payproOpts.toAddress)
            return false;
        if (txp.coin == 'bch' && (new BCHAddress(toAddress).toString()) != (new BCHAddress(payproOpts.toAddress).toString()))
            return false;
        return true;
    };
    Verifier.checkTxProposal = function (credentials, txp, opts) {
        opts = opts || {};
        if (!this.checkTxProposalSignature(credentials, txp))
            return false;
        if (opts.paypro && !this.checkPaypro(txp, opts.paypro))
            return false;
        return true;
    };
    return Verifier;
}());
exports.Verifier = Verifier;
//# sourceMappingURL=verifier.js.map