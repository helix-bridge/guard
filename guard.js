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
          row: 100) {records {id, messageNonce, recvTokenAddress, recipient, recvAmount, endTime, guardSignatures}}}`;
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

function generateDataHash(web3, depositor, transferId, timestamp, token, recipient, amount, chainId, contractAddress) {
    const claimSign = web3.eth.abi.encodeFunctionSignature("claim(address,uint256,uint256,address,address,uint256,bytes[])");
    const id = web3.eth.abi.encodeParameters(['address', 'uint256', 'uint256', 'address', 'address', 'uint256'], [depositor, transferId, timestamp, token, recipient, amount]);
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

const loop = async function(passwd) {
    var config = require('./config.json');
    var web3 = new Web3(Web3.givenProvider);
    const key = config.private_key;
    const privateKey = decrypt(key, passwd);
    web3.eth.accounts.wallet.add(privateKey);

    console.log("start to listen guard");
    while (true) {
        try {
            const records = await queryRecordNeedSignature(
                config.server,
                config.fromChain,
                config.toChain,
                config.bridge,
                web3.eth.accounts.wallet[0].address.toLowerCase()
            );
            if (records.length > 0) {
                console.log("find new records need to be signed", records.length);
                for (const record of records) {
                    console.log(`start to sign record, id: ${record.id}`);
                    const splitIds = record.id.split('-');
                    const dataHash = generateDataHash(
                        web3,
                        config.depositor,
                        BigInt(splitIds[splitIds.length-1]).toString(),
                        record.endTime,
                        record.recvTokenAddress,
                        record.recipient,
                        record.recvAmount,
                        config.toChainId,
                        config.guard_contract);
                    const signature = ethUtil.ecsign(Buffer.from(dataHash.substr(2), 'hex'), Buffer.from(privateKey.substr(2), 'hex'));
                    await addSignature(config.server, record.id, ethUtil.toRpcSig(signature.v, signature.r, signature.s));
                }
            }
        } catch(err) {
            console.log("error", err);
        }
        await wait(10000);
    }
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
    });
    hidePasswd(rl);
}

