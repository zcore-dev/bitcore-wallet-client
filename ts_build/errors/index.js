'use strict';
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var _ = __importStar(require("lodash"));
function format(message, args) {
    return message
        .replace('{0}', args[0])
        .replace('{1}', args[1])
        .replace('{2}', args[2]);
}
var traverseNode = function (parent, errorDefinition) {
    var NodeError = function () {
        if (_.isString(errorDefinition.message)) {
            this.message = format(errorDefinition.message, arguments);
        }
        else if (_.isFunction(errorDefinition.message)) {
            this.message = errorDefinition.message.apply(null, arguments);
        }
        else {
            throw new Error('Invalid error definition for ' + errorDefinition.name);
        }
        this.stack = this.message + '\n' + (new Error()).stack;
    };
    NodeError.prototype = Object.create(parent.prototype);
    NodeError.prototype.name = parent.prototype.name + errorDefinition.name;
    parent[errorDefinition.name] = NodeError;
    if (errorDefinition.errors) {
        childDefinitions(NodeError, errorDefinition.errors);
    }
    return NodeError;
};
var childDefinitions = function (parent, childDefinitions) {
    _.each(childDefinitions, function (childDefinition) {
        traverseNode(parent, childDefinition);
    });
};
var traverseRoot = function (parent, errorsDefinition) {
    childDefinitions(parent, errorsDefinition);
    return parent;
};
var bwc = {};
bwc.Error = function () {
    this.message = 'Internal error';
    this.stack = this.message + '\n' + (new Error()).stack;
};
bwc.Error.prototype = Object.create(Error.prototype);
bwc.Error.prototype.name = 'bwc.Error';
var data = require('./spec');
traverseRoot(bwc.Error, data);
module.exports = bwc.Error;
module.exports.extend = function (spec) {
    return traverseNode(bwc.Error, spec);
};
//# sourceMappingURL=index.js.map