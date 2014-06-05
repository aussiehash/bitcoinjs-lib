(function () {
  var Script = Bitcoin.Script;

  var Transaction = Bitcoin.Transaction = function (doc) {
    this.version = 1;
    this.lock_time = 0;
    this.ins = [];
    this.outs = [];
    this.timestamp = null;
    this.block = null;

    if (doc) {
      if (typeof doc === 'string' || Array.isArray(doc))
        doc = Transaction.deserialize(doc);
      if (doc.hash) this.hash = doc.hash;
      if (doc.version) this.version = doc.version;
      if (doc.lock_time) this.lock_time = doc.lock_time;
      if (doc.ins && doc.ins.length) {
        for (var i = 0; i < doc.ins.length; i++) {
          this.addInput(new TransactionIn(doc.ins[i]));
        }
      }
      if (doc.outs && doc.outs.length) {
        for (var i = 0; i < doc.outs.length; i++) {
          this.addOutput(new TransactionOut(doc.outs[i]));
        }
      }
      if (doc.timestamp) this.timestamp = doc.timestamp;
      if (doc.block) this.block = doc.block;
    }
  };

  /**
   * Turn transaction data into Transaction objects.
   *
   * Takes an array of plain JavaScript objects containing transaction data and
   * returns an array of Transaction objects.
   */
  Transaction.objectify = function (txs) {
    var objs = [];
    for (var i = 0; i < txs.length; i++) {
      objs.push(new Transaction(txs[i]));
    }
    return objs;
  };

  /**
   * Create a new txin.
   *
   * Can be called with an existing TransactionIn object to add it to the
   * transaction. Or it can be called with a Transaction object and an integer
   * output index, in which case a new TransactionIn object pointing to the
   * referenced output will be created.
   *
   * Note that this method does not sign the created input.
   */
  Transaction.prototype.addInput = function (tx, outIndex) {
    if (arguments[0] instanceof TransactionIn) {
      this.ins.push(arguments[0]);
    } else {
      this.ins.push(new TransactionIn({
        outpoint: {
          hash: tx.hash,
          index: outIndex
        },
        script: new Bitcoin.Script(),
        sequence: 4294967295
      }));
    }
  };

  /**
   * Create a new txout.
   *
   * Can be called with an existing TransactionOut object to add it to the
   * transaction. Or it can be called with an Address object and a BigInteger
   * for the amount, in which case a new TransactionOut object with those
   * values will be created.
   */
  Transaction.prototype.addOutput = function (address, value) {
    if (arguments[0] instanceof TransactionOut) {
      this.outs.push(arguments[0]);
    } else {
      if (value instanceof BigInteger) {
        value = value.toByteArrayUnsigned().reverse();
        while (value.length < 8) value.push(0);
      } else if (Bitcoin.Util.isArray(value)) {
        // Nothing to do
      }

      this.outs.push(new TransactionOut({
        value: value,
        script: Script.createOutputScript(address)
      }));
    }
  };

  /**
   * Serialize this transaction.
   *
   * Returns the transaction as a byte array in the standard Bitcoin binary
   * format. This method is byte-perfect, i.e. the resulting byte array can
   * be hashed to get the transaction's standard Bitcoin hash.
   */
  Transaction.prototype.serialize = function ()
  {
    var buffer = [];
    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(this.version)]).reverse());
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(this.ins.length));
    for (var i = 0; i < this.ins.length; i++) {
      var txin = this.ins[i];
      buffer = buffer.concat(Crypto.util.base64ToBytes(txin.outpoint.hash));
      buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(txin.outpoint.index)]).reverse());
      var scriptBytes = txin.script.buffer;
      buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
      buffer = buffer.concat(scriptBytes);
      buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(txin.sequence)]).reverse());
    }
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(this.outs.length));
    for (var i = 0; i < this.outs.length; i++) {
      var txout = this.outs[i];
      buffer = buffer.concat(txout.value);
      var scriptBytes = txout.script.buffer;
      buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
      buffer = buffer.concat(scriptBytes);
    }
    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(this.lock_time)]).reverse());

    return buffer;
  };

  Transaction.deserialize = function(buffer) {
    var pos = 0,
        obj = { ins: [], outs: [] },
        insCount, outsCount, i;

    if (typeof buffer === 'string')
        buffer = Crypto.util.hexToBytes(buffer);

    obj.version = readAsInt(4);

    insCount = readVarInt();
    for (i = 0; i < insCount; i++) {
      obj.ins.push({
        outpoint: {
          hash: Crypto.util.bytesToHex(readBytes(32).reverse()),
          index: readAsInt(4)
        },
        script: new Script(readVarString()),
        sequence: readBytes(4)
      });
    }

    outsCount = readVarInt();
    for (i = 0; i < outsCount; i++) {
      obj.outs.push({
        value: bytesToNum(readBytes(8)).toString(),
        script: new Script(readVarString())
      });
    }

    obj.locktime = readAsInt(4);
    return new Transaction(obj);

    function readAsInt(bytes) {
      if (bytes === 0) return 0;
      pos++;
      return buffer[pos-1] + readAsInt(bytes-1) * 256;
    }

    function readVarInt() {
      var bytes = buffer.slice(pos, pos + 9); // maximum possible number of bytes to read
      var result = varIntToNum(bytes);

      pos += result.bytes.length;
      return result.number;
    }

    function readBytes(bytes) {
      pos += bytes;
      return buffer.slice(pos - bytes, pos);
    }

    function readVarString() {
      var size = readVarInt();
      return readBytes(size);
    }

    function bytesToNum(bytes) {
      if (bytes.length === 0) return 0;
      return bytes[0] + 256 * bytesToNum(bytes.slice(1));
    }

    function varIntToNum(bytes) {
      var prefix = bytes[0];

      var viBytes =
          prefix < 253   ? bytes.slice(0, 1)
        : prefix === 253 ? bytes.slice(1, 3)
        : prefix === 254 ? bytes.slice(1, 5)
        : bytes.slice(1, 9);

      return {
        bytes: prefix < 253 ? viBytes : bytes.slice(0, viBytes.length + 1),
        number: bytesToNum(viBytes)
      };
    }
  };

  var OP_CODESEPARATOR = 171;

  var SIGHASH_ALL = 1;
  var SIGHASH_NONE = 2;
  var SIGHASH_SINGLE = 3;
  var SIGHASH_ANYONECANPAY = 80;

  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input. This
   * method copies the transaction, makes the necessary changes based on the
   * hashType, serializes and finally hashes the result. This hash can then be
   * used to sign the transaction input in question.
   */
  Transaction.prototype.hashTransactionForSignature =
  function (connectedScript, inIndex, hashType)
  {
    var txTmp = this.clone();

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible
    // incompatibilities.
    /*scriptCode = scriptCode.filter(function (val) {
     return val !== OP_CODESEPARATOR;
     });*/

    // Blank out other inputs' signatures
    for (var i = 0; i < txTmp.ins.length; i++) {
      txTmp.ins[i].script = new Script();
    }

    txTmp.ins[inIndex].script = connectedScript;

    // Blank out some of the outputs
    if ((hashType & 0x1f) == SIGHASH_NONE) {
      txTmp.outs = [];

      // Let the others update at will
      for (var i = 0; i < txTmp.ins.length; i++)
        if (i != inIndex)
          txTmp.ins[i].sequence = 0;
    } else if ((hashType & 0x1f) == SIGHASH_SINGLE) {
      // TODO: Implement
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (hashType & SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
    }

    var buffer = txTmp.serialize();

    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(hashType)]).reverse());

    var hash1 = Crypto.SHA256(buffer, {asBytes: true});

    return Crypto.SHA256(hash1, {asBytes: true});
  };

  /**
   * Calculate and return the transaction's hash.
   */
  Transaction.prototype.getHash = function ()
  {
    var buffer = this.serialize();
    return Crypto.SHA256(Crypto.SHA256(buffer, {asBytes: true}), {asBytes: true});
  };

  /**
   * Create a copy of this transaction object.
   */
  Transaction.prototype.clone = function ()
  {
    var newTx = new Transaction();
    newTx.version = this.version;
    newTx.lock_time = this.lock_time;
    for (var i = 0; i < this.ins.length; i++) {
      var txin = this.ins[i].clone();
      newTx.addInput(txin);
    }
    for (var i = 0; i < this.outs.length; i++) {
      var txout = this.outs[i].clone();
      newTx.addOutput(txout);
    }
    return newTx;
  };

  /**
   * Analyze how this transaction affects a wallet.
   *
   * Returns an object with properties 'impact', 'type' and 'addr'.
   *
   * 'impact' is an object, see Transaction#calcImpact.
   *
   * 'type' can be one of the following:
   *
   * recv:
   *   This is an incoming transaction, the wallet received money.
   *   'addr' contains the first address in the wallet that receives money
   *   from this transaction.
   *
   * self:
   *   This is an internal transaction, money was sent within the wallet.
   *   'addr' is undefined.
   *
   * sent:
   *   This is an outgoing transaction, money was sent out from the wallet.
   *   'addr' contains the first external address, i.e. the recipient.
   *
   * other:
   *   This method was unable to detect what the transaction does. Either it
   */
  Transaction.prototype.analyze = function (wallet) {
    if (!(wallet instanceof Bitcoin.Wallet)) return null;

    var allFromMe = true,
    allToMe = true,
    firstRecvHash = null,
    firstMeRecvHash = null,
    firstSendHash = null,
    recvHashVersion = wallet.addressVersion;

    for (var i = this.outs.length-1; i >= 0; i--) {
      var txout = this.outs[i];
      var hash = txout.script.simpleOutPubKeyHash();
      if (!wallet.hasHash(hash)) {
        allToMe = false;
      } else {
        firstMeRecvHash = hash;
      }
      if (!wallet.hasInternalHash(hash)) {
        firstRecvHash = hash;
        if (txout.script.getOutType() === 'Scripthash') {
          recvHashVersion = wallet.scriptHashVersion;
        }
      }
    }
    for (var i = this.ins.length-1; i >= 0; i--) {
      var txin = this.ins[i];
      if (txin.isCoinbase()) {
        continue;
      }
      try {
        firstSendHash = txin.script.simpleInPubKeyHash();
      } catch (e) {
        console.error('Failed to compute simpleInPubKeyHash:', e);
        firstSendHash = null;
      }
      if (firstSendHash) {
        if (!wallet.hasHash(firstSendHash)) {
          allFromMe = false;
          break;
        }
      } else {
        var hashes = txin.script.recoverInPubKeyHashes(this.hash),
            allMissing = true;
        for (var j = 0; j < hashes.length; j++) {
          if (wallet.hasHash(hashes[j])) {
            allMissing = false;
            break;
          }
        }
        if (allMissing) {
          allFromMe = false;
        }
      }
    }

    var impact = this.calcImpact(wallet);

    var analysis = {};

    analysis.impact = impact;

    if (impact.sign > 0 && impact.value.compareTo(BigInteger.ZERO) > 0) {
      analysis.type = 'recv';
      analysis.addr = new Bitcoin.Address(firstMeRecvHash, recvHashVersion);
    } else if (allFromMe && allToMe) {
      analysis.type = 'self';
    } else if (allFromMe) {
      analysis.type = 'sent';
      analysis.addr = new Bitcoin.Address(firstRecvHash, recvHashVersion);
    } else  {
      analysis.type = "other";
    }

    return analysis;
  };

  /**
   * Get a human-readable version of the data returned by Transaction#analyze.
   *
   * This is merely a convenience function. Clients should consider implementing
   * this themselves based on their UI, I18N, etc.
   */
  Transaction.prototype.getDescription = function (wallet) {
    var analysis = this.analyze(wallet);

    if (!analysis) return "";

    switch (analysis.type) {
    case 'recv':
      return "Received with "+analysis.addr;
      break;

    case 'sent':
      return "Payment to "+analysis.addr;
      break;

    case 'self':
      return "Payment to yourself";
      break;

    case 'other':
    default:
      return "";
    }
  };

  /**
   * Get the total amount of a transaction's outputs.
   */
  Transaction.prototype.getTotalOutValue = function () {
    var totalValue = BigInteger.ZERO;
    for (var j = 0; j < this.outs.length; j++) {
      var txout = this.outs[j];
      totalValue = totalValue.add(Bitcoin.Util.valueToBigInt(txout.value));
    }
    return totalValue;
  };

   /**
    * Old name for Transaction#getTotalOutValue.
    *
    * @deprecated
    */
   Transaction.prototype.getTotalValue = Transaction.prototype.getTotalOutValue;

  /**
   * Calculates the impact a transaction has on this wallet.
   *
   * Based on the its public keys, the wallet will calculate the
   * credit or debit of this transaction.
   *
   * It will return an object with two properties:
   *  - sign: 1 or -1 depending on sign of the calculated impact.
   *  - value: amount of calculated impact
   *
   * @returns Object Impact on wallet
   */
  Transaction.prototype.calcImpact = function (wallet) {
    if (!(wallet instanceof Bitcoin.Wallet)) return BigInteger.ZERO;

    // Calculate credit to us from all outputs
    var valueOut = BigInteger.ZERO;
    for (var j = 0; j < this.outs.length; j++) {
      var txout = this.outs[j];
      var hash = Crypto.util.bytesToBase64(txout.script.simpleOutPubKeyHash());
      if (wallet.hasHash(hash)) {
        valueOut = valueOut.add(Bitcoin.Util.valueToBigInt(txout.value));
      }
    }

    // Calculate debit to us from all ins
    var valueIn = BigInteger.ZERO;
    for (var j = 0; j < this.ins.length; j++) {
      var txin = this.ins[j];
      if (txin.isCoinbase()) {
        continue;
      }
      var hash = null;
      try {
        hash = Crypto.util.bytesToBase64(txin.script.simpleInPubKeyHash());
      } catch (e) {
        console.error('Failed to compute simpleInPubKeyHash:', e);
        var hashes = txin.script.recoverInPubKeyHashes(this.hash);
        for (var k = 0; k < hashes.length; k++) {
          if (wallet.hasHash(hashes[k])) {
            hash = hashes[k];
            break;
          }
        }
      }
      if (hash && wallet.hasHash(hash)) {
        var fromTx = wallet.txIndex[txin.outpoint.hash];
        if (fromTx) {
          valueIn = valueIn.add(Bitcoin.Util.valueToBigInt(fromTx.outs[txin.outpoint.index].value));
        }
      }
    }
    if (valueOut.compareTo(valueIn) >= 0) {
      return {
        sign: 1,
        value: valueOut.subtract(valueIn)
      };
    } else {
      return {
        sign: -1,
        value: valueIn.subtract(valueOut)
      };
    }
  };

  var TransactionIn = Bitcoin.TransactionIn = function (data)
  {
    this.outpoint = data.outpoint;
    if (data.script instanceof Script) {
      this.script = data.script;
    } else {
      this.script = new Script(data.script);
    }
    this.sequence = data.sequence;
  };

  TransactionIn.prototype.isCoinbase = function ()
  {
    return (
      this.outpoint.hash.match(/0+/) &&
      this.outpoint.index === -1
    );
  };

  TransactionIn.prototype.clone = function ()
  {
    var newTxin = new TransactionIn({
      outpoint: {
        hash: this.outpoint.hash,
        index: this.outpoint.index
      },
      script: this.script.clone(),
      sequence: this.sequence
    });
    return newTxin;
  };

  var TransactionOut = Bitcoin.TransactionOut = function (data)
  {
    if (data.script instanceof Script) {
      this.script = data.script;
    } else {
      this.script = new Script(data.script);
    }

    if (Bitcoin.Util.isArray(data.value)) {
      this.value = data.value;
    } else if ("string" == typeof data.value) {
      var valueHex = (new BigInteger(data.value, 10)).toString(16);
      while (valueHex.length < 16) valueHex = "0" + valueHex;
      this.value = Crypto.util.hexToBytes(valueHex);
    }
  };

  TransactionOut.prototype.clone = function ()
  {
    var newTxout = new TransactionOut({
      script: this.script.clone(),
      value: this.value.slice(0)
    });
    return newTxout;
  };
})();
