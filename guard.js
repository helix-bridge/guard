const Web3 = require('web3');
const ethUtil = require('ethereumjs-util');
var axios = require('axios');
var crypto = require('crypto');
var readline = require('readline');

function encrypt(str,secret){
    iv = crypto.randomBytes(16);
	var cipher = crypto.createCipheriv('aes-256-ctr',Buffer.from(secret, 'hex'), iv);
    let encrypted = cipher.update(str);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(str,secret){
    let encrySplit = str.split(':');
    let iv = Buffer.from(encrySplit.shift(), 'hex');
    let encrypted = Buffer.from(encrySplit.join(':'), 'hex');
	var decipher = crypto.createDecipheriv('aes-256-ctr',Buffer.from(secret, 'hex'), iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

function acceptPasswd() {
    var rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.stdoutMuted = true;
    return rl;
}

function hidePasswd(rl) {
    rl._writeToOutput = function _writeToOutput(stringToWrite) {
        if (rl.stdoutMuted)
            rl.output.write("*");
        else
            rl.output.write(stringToWrite);
    };
}

function wait(ms) {
    return new Promise(resolve => setTimeout(() => resolve(), ms));
};

async function queryRecordNeedSignature(url, fromChain, toChain, bridge, guardAddress) {
    const query = `query {
      queryGuardNeedSignature(
          fromChain: \"${fromChain}\",
          toChain: \"${toChain}\",
          bridge: \"${bridge}\",
          guardAddress: \"${guardAddress}\",
          row: 100) {records {id, messageNonce, recvTokenAddress, recipient, recvAmount, endTime, guardSignatures, extData}}}`;
    const records = await axios
        .post(url, {
            query,
            variables: null,
        })
        .then((res) => res.data.data.queryGuardNeedSignature);
    return records.records;
}

async function addSignature(url, id, signature) {
    const mutation = `mutation {
      addGuardSignature(
        id: \"${id}\",
        signature: \"${signature}\")}`
    await axios.post(url, {
        query: mutation,
        variables: null,
    })
}

function generateDataHash(web3, depositor, transferId, timestamp, token, amount, chainId, contractAddress, extData) {
    const claimSign = web3.eth.abi.encodeFunctionSignature("claim(address,uint256,uint256,address,uint256,bytes,bytes[])");
    console.log(depositor, transferId, timestamp, token, amount, extData);
    const id = web3.eth.abi.encodeParameters(['address', 'uint256', 'uint256', 'address', 'uint256', 'bytes'], [depositor, transferId, timestamp, token, amount, extData]);
    const message = web3.eth.abi.encodeParameters(['bytes4', 'bytes'], [claimSign, id]);
    const structHash = web3.utils.keccak256(message);
    const DOMAIN_SEPARATOR_TYPEHASH = web3.utils.keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    domainSeparator = web3.utils.keccak256(
        web3.eth.abi.encodeParameters(
            ['bytes32', 'uint256', 'address'],
            [DOMAIN_SEPARATOR_TYPEHASH, chainId, contractAddress]
        )
    );
    return web3.utils.keccak256('0x1901' + domainSeparator.substring(2) + structHash.substring(2));
}

function signGuardClaim(web3, depositor, transferId, endTime, recvTokenAddress, recvAmount, toChainId, extData, guardContract, privateKey) {
    const dataHash = generateDataHash(
        web3,
        depositor,
        transferId,
        endTime,
        recvTokenAddress,
        recvAmount,
        toChainId,
        guardContract,
        extData
    );
    const signature = ethUtil.ecsign(Buffer.from(dataHash.substr(2), 'hex'), Buffer.from(privateKey.substr(2), 'hex'));
    console.log(signature);
    console.log(ethUtil.toRpcSig(signature.v, signature.r, signature.s));
}

const loop = async function(passwd) {
    var config = require('./config.json');
    var web3 = new Web3(Web3.givenProvider);

    console.log("start to listen guard");
    const key = config.private_key;
    const privateKey = decrypt(key, passwd);
    web3.eth.accounts.wallet.add(privateKey);
    const address = web3.eth.accounts.wallet[0].address.toLowerCase();

    while (true) {
        for (const bridge of config.bridges) {
          try {
              const records = await queryRecordNeedSignature(
                  config.server,
                  bridge.fromChain,
                  bridge.toChain,
                  bridge.bridge,
                  address,
              );
              if (records.length > 0) {
                  console.log("find new records need to be signed", records.length);
                  for (const record of records) {
                      console.log(`start to sign record, id: ${record.id}`);
                      const splitIds = record.id.split('-');
                      const dataHash = generateDataHash(
                          web3,
                          bridge.depositor,
                          BigInt(splitIds[splitIds.length-1]).toString(),
                          record.endTime,
                          record.recvTokenAddress,
                          record.recvAmount,
                          bridge.toChainId,
                          bridge.guard_contract,
                          record.extData,
                      );
                      const signature = ethUtil.ecsign(Buffer.from(dataHash.substr(2), 'hex'), Buffer.from(privateKey.substr(2), 'hex'));
                      await addSignature(config.server, record.id, ethUtil.toRpcSig(signature.v, signature.r, signature.s));
                  }
              }
          } catch(err) {
              console.log("error", err);
          }
        }
        await wait(10000);
    }
}

function sign(passwd) {
    var config = require('./config.json');
    var web3 = new Web3(Web3.givenProvider);
    const key = config.private_key;
    const privateKey = decrypt(key, passwd);
    web3.eth.accounts.wallet.add(privateKey);
    // get the tx event from chain
    const depositor = "0xAB0b1CB19e00eCf0DCcF8b3e201030a2556625e3";
    const transferId = "0x1dbbd1ee04c24e0018664f350f5130747775b4cb5090d757fea6689de5228b2b";
    const endTime = 1711118652;
    const recvTokenAddress = "0xD1EB53E6b313d2849243F579e0fCd4dbCab56062";
    const recvAmount = "0xae56f730e6d840000";
    const toChainId = 11155111;
    const recipient = "0x88A39B052D477CFDE47600A7C9950A441CE61CB4";
    const guardContract = "0x4CA75992d2750BEC270731A72DfDedE6b9E71cC7";
    const xRingConvertor = "0xC39309C45203324531FBAAB791C42FFC619396C5";
    //let extData = web3.eth.abi.encodeParameters(['address', 'bytes'], [recipient, "0x"]);
    let extData = web3.eth.abi.encodeParameters(['address', 'bytes'], [xRingConvertor, recipient]);
    signGuardClaim(web3, depositor, transferId, endTime, recvTokenAddress, recvAmount, toChainId, extData, guardContract, privateKey);
}

if (process.argv.length == 4) {
    const privateKey = process.argv[2];
    const password = process.argv[3];
    const passwd = password.padStart(64, '0');
    console.log(encrypt(privateKey, passwd));
} else {
    var rl = acceptPasswd();
    rl.question('Password: ', function(password) {
        rl.close();
        const passwd = password.padStart(64, '0');
        loop(passwd);
        //sign(passwd);
    });
    hidePasswd(rl);
}

