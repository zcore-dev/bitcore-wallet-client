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
var request = require('superagent');
var async = require('async');
var Package = require('../package.json');
var log = require('./log');
var util = require('util');
var Errors = require('./errors');
var Request = (function () {
    function Request(url, opts) {
        this.baseUrl = url;
        this.r = opts.r || request;
        this.session = null;
        this.credentials = null;
    }
    Request.prototype.setCredentials = function (credentials) {
        this.credentials = credentials;
    };
    Request.prototype.getHeaders = function (method, url, args) {
        var headers = {
            'x-client-version': 'bwc-' + Package.version
        };
        if (this.supportStaffWalletId) {
            headers['x-wallet-id'] = this.supportStaffWalletId;
        }
        return headers;
    };
    Request._signRequest = function (method, url, args, privKey) {
        var message = [method.toLowerCase(), url, JSON.stringify(args)].join('|');
        return common_1.Utils.signMessage(message, privKey);
    };
    Request.prototype.doRequest = function (method, url, args, useSession, cb) {
        var headers = this.getHeaders(method, url, args);
        if (this.credentials) {
            headers['x-identity'] = this.credentials.copayerId;
            if (useSession && this.session) {
                headers['x-session'] = this.session;
            }
            else {
                var reqSignature;
                var key = args._requestPrivKey || this.credentials.requestPrivKey;
                if (key) {
                    delete args['_requestPrivKey'];
                    reqSignature = Request._signRequest(method, url, args, key);
                }
                headers['x-signature'] = reqSignature;
            }
        }
        var r = this.r[method](this.baseUrl + url);
        r.accept('json');
        _.each(headers, function (v, k) {
            if (v)
                r.set(k, v);
        });
        if (args) {
            if (method == 'post' || method == 'put') {
                r.send(args);
            }
            else {
                r.query(args);
            }
        }
        r.timeout(this.timeout);
        r.end(function (err, res) {
            if (!res) {
                return cb(new Errors.CONNECTION_ERROR());
            }
            if (res.body)
                log.debug(util.inspect(res.body, {
                    depth: 10
                }));
            if (res.status !== 200) {
                if (res.status === 503)
                    return cb(new Errors.MAINTENANCE_ERROR());
                if (res.status === 404)
                    return cb(new Errors.NOT_FOUND());
                if (!res.status)
                    return cb(new Errors.CONNECTION_ERROR());
                log.error('HTTP Error:' + res.status);
                if (!res.body)
                    return cb(new Error(res.status));
                return cb(Request._parseError(res.body));
            }
            if (res.body === '{"error":"read ECONNRESET"}')
                return cb(new Errors.ECONNRESET_ERROR(JSON.parse(res.body)));
            return cb(null, res.body, res.header);
        });
    };
    Request._parseError = function (body) {
        if (!body)
            return;
        if (_.isString(body)) {
            try {
                body = JSON.parse(body);
            }
            catch (e) {
                body = {
                    error: body
                };
            }
        }
        var ret;
        if (body.code) {
            if (Errors[body.code]) {
                ret = new Errors[body.code]();
                if (body.message)
                    ret.message = body.message;
            }
            else {
                ret = new Error(body.code +
                    ': ' +
                    (_.isObject(body.message)
                        ? JSON.stringify(body.message)
                        : body.message));
            }
        }
        else {
            ret = new Error(body.error || JSON.stringify(body));
        }
        log.error(ret);
        return ret;
    };
    Request.prototype.post = function (url, args, cb) {
        return this.doRequest('post', url, args, false, cb);
    };
    Request.prototype.put = function (url, args, cb) {
        return this.doRequest('put', url, args, false, cb);
    };
    Request.prototype.get = function (url, cb) {
        url += url.indexOf('?') > 0 ? '&' : '?';
        url += 'r=' + _.random(10000, 99999);
        return this.doRequest('get', url, {}, false, cb);
    };
    Request.prototype.getWithLogin = function (url, cb) {
        url += url.indexOf('?') > 0 ? '&' : '?';
        url += 'r=' + _.random(10000, 99999);
        return this.doRequestWithLogin('get', url, {}, cb);
    };
    Request.prototype._login = function (cb) {
        this.post('/v1/login', {}, cb);
    };
    Request.prototype.logout = function (cb) {
        this.post('/v1/logout', {}, cb);
    };
    Request.prototype.doRequestWithLogin = function (method, url, args, cb) {
        var _this = this;
        async.waterfall([
            function (next) {
                if (_this.session)
                    return next();
                _this.doLogin(next);
            },
            function (next) {
                _this.doRequest(method, url, args, true, function (err, body, header) {
                    if (err && err instanceof Errors.NOT_AUTHORIZED) {
                        _this.doLogin(function (err) {
                            if (err)
                                return next(err);
                            return _this.doRequest(method, url, args, true, next);
                        });
                    }
                    next(null, body, header);
                });
            }
        ], cb);
    };
    Request.prototype.doLogin = function (cb) {
        var _this = this;
        this._login(function (err, s) {
            if (err)
                return cb(err);
            if (!s)
                return cb(new Errors.NOT_AUTHORIZED());
            _this.session = s;
            cb();
        });
    };
    Request.prototype.delete = function (url, cb) {
        return this.doRequest('delete', url, {}, false, cb);
    };
    return Request;
}());
exports.Request = Request;
//# sourceMappingURL=request.js.map