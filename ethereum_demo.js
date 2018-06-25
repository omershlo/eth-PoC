//let bitcoin = require('bitcoinjs-lib')
//const signM = require('./sign');
//const signMPC = signM.sign;
const KeyGenM = require('./KeyGen_v2');
const KeyGenMPC = KeyGenM.KeyGen;

//const btcClient = require('./btcClient')
//var querystring = require('querystring');
//var http = require('http');
//const crypto = require('crypto');
//const BigInteger = require('big-integer');
//const EC = require('elliptic').ec;
const Consts = require('./consts');
const utils = require('./utils');
//const pickRandom = utils.pickRandom;
//const pickRandomInRange = utils.pickRandomInRange;
//const modulo = utils.modulo;
//const moduloPow = utils.moduloPow;
//const KeyPairBuilder = require('./paillier/keypair-builder');

const EthereumTx = require('./ethereumjs-tx/index');
const EthereumTx2 = require('./ethereumjs-tx/index2');
var api = require('./ethereumjs-tx/etherscan-api/index').init('CGMFP65SFQTWQ2N6DYWDPKREEVBJIR9T8D','ropsten');

var Web3 = require('web3');
//var web3 = new Web3(new Web3("http://localhost:8545"));
var web3 = new Web3(new Web3.providers.HttpProvider("https://ropsten.infura.io/ "));
mpcSignParams = keyGenReceiveFunds();
//sendFunds(mpcSignParams);
/*******************************************/

function keyGenReceiveFunds(){
  
  const {serverCache,clientCache} = KeyGenMPC();
  const Q1 = utils.ec.curve.point(serverCache['q1'].x.toString('hex'),serverCache['q1'].y.toString('hex'));
  const Q2 = utils.ec.curve.point(clientCache['q2'].x.toString('hex'),clientCache['q2'].y.toString('hex'));
  const X1 = serverCache['x1'].toString(Consts.HEX);
  const X2 = clientCache['x2'].toString(Consts.HEX);
  const Q = Q1.mul(X2.toString(Consts.HEX)).x.toString('hex');
  const Ckey = clientCache['ciphertext'].toString(Consts.HEX);
    const n = clientCache['paillierPublicKey'].n.toString(Consts.HEX);
  const g = clientCache['paillierPublicKey'].g.toString(Consts.HEX);
  const p = serverCache['keyPair'].privateKey.p.toString(Consts.HEX);
  const q = serverCache['keyPair'].privateKey.q.toString(Consts.HEX);
  const lambda = serverCache['keyPair'].privateKey.lambda.toString(Consts.HEX);
  const preCalculatedDenominator = serverCache['keyPair'].privateKey.preCalculatedDenominator.toString(Consts.HEX);
  
  const mpcSignParams = {Q1:Q1,Q2:Q2,Q:Q,Ckey:Ckey,X1:X1,X2:X2,n:n,g:g,p:p,q:q,lambda:lambda,preCalculatedDenominator:preCalculatedDenominator};
  console.log('Q1x: '+Q1.x.toString('hex'))
  console.log(' ')
  console.log('Q1y: '+Q1.y.toString('hex'))
  console.log(' ')
  console.log('Q2x: '+Q2.x.toString('hex'))
  console.log(' ')
  console.log('Q2y: '+Q2.y.toString('hex'))
  console.log(' ')
  console.log('Q: '+ Q)
  console.log(' ')
  console.log('Ckey: '+Ckey)
  console.log(' ')
  console.log('X1: '+X1)
  console.log(' ')
  console.log('X2: '+X2)
  console.log(' ')
  console.log('n: '+n)
  console.log(' ')
  console.log('g: '+g)
  console.log(' ')
  console.log('p: '+p)
  console.log(' ')
  console.log('q: '+q)
  console.log(' ')
  console.log('lambda: '+ lambda)
  console.log(' ')
  console.log('preCalculatedDenominator: '+preCalculatedDenominator)
  /// creare address
  //var Web3 = require('web3');
  //var web3 = new Web3(new Web3("http://localhost:8545"));
  ////var web3 = new Web3(new Web3.providers.HttpProvider("https://ropsten.infura.io/ "));
  
  const Qp = Q1.mul(X2.toString(Consts.HEX));
  Q64 = Qp.x.toString('hex')+Qp.y.toString('hex');
  
  //var hash = web3.sha3(Q64,'hex');
  //const addressEth = hash.slice(26);
  const ethUtil = require('./ethereumjs-tx/ethereumjs-util/index');
  const addressEthBuf = ethUtil.publicToAddress(new Buffer(Q64, 'hex'));
  const addressEth = addressEthBuf.toString('hex');
  console.log('Address: 0x'+ addressEth)
  
  // send money to addressEth
  var count = web3.eth.getTransactionCount("0x112e1304260Dee1504B75721fe0a2dFB3aFe71e7");
  const txParams = {
    //nonce: '0x15',  // make sure its updated, maybe there an automatic way for doing this
    nonce: web3.toHex(count),
    gasPrice: '0x4a817c800', 
    gasLimit: '0x5308',
    to: '0x'+addressEth, 
    value: '0x8af3107a400000', 
    data: '0x0',
    // EIP 155 chainId - mainnet: 1, ropsten: 3
    chainId: 3
  }

  const tx = new EthereumTx(txParams);
  var privateKey = new Buffer('0ad580b4030f6e9ab7408f319d99ed5cff1f27d36f2e35e649aa0b9e5d011e0f', 'hex');
  tx.sign(privateKey);
  //tx.sign2(mpcSignParams,addressEth)
  console.log(tx)
  console.log(tx.serialize().toString('hex'))
  serializedTx = tx.serialize().toString('hex');

  //var balance = api.account.balance('0xf111b4d5a8b7ce318d48b403b094398f3c0f43fb');
  var srt1 = api.proxy.eth_sendRawTransaction(tx.serialize().toString('hex'));
  
  srt1.then(function(txID){
    console.log('txID: ' + txID.result);
  
    
  });
  setTimeout(sendFunds,120000,mpcSignParams);
  return;
 // end of part 1 comment
  
}

// send money using mpc signing
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


function sendFunds(mpcSignParams){

//  await sleep(100000);
//  console.log('tx confirmed'); // possible to insert here an api call to check the status of the txid
/// creare address


//var Web3 = require('web3');
//var web3 = new Web3(new Web3("http://localhost:8545"));
////var web3 = new Web3(new Web3.providers.HttpProvider("https://ropsten.infura.io/ "));

  const Qp = mpcSignParams.Q1.mul(mpcSignParams.X2.toString(Consts.HEX));
  const Q64 = Qp.x.toString('hex')+Qp.y.toString('hex');
  
  //console.log(Q64)
  //var hash = web3.sha3(Q64,'hex');
  //const addressEth = hash.slice(26);
  
  const ethUtil = require('./ethereumjs-tx/ethereumjs-util/index')
  const addressEthBuf = ethUtil.publicToAddress(new Buffer(Q64, 'hex'));
  const addressEth = addressEthBuf.toString('hex');
  console.log('Address: '+ addressEth)
  
  const txParams2 = {
    nonce: '0x1',
    gasPrice: '0x4a817c800', 
    gasLimit: '0x5318',
    to: '0x112e1304260Dee1504B75721fe0a2dFB3aFe71e7', 
    value: '0x5af3107a40000', 
    data: '0x0',
    // EIP 155 chainId - mainnet: 1, ropsten: 3
    chainId: 3
  }
  
  const tx2 = new EthereumTx2(txParams2);
  tx2.sign2(mpcSignParams,addressEth)
  console.log(tx2)
  console.log(tx2.serialize().toString('hex'))
  serializedTx2 = tx2.serialize().toString('hex');
  //var balance = api.account.balance('0xf111b4d5a8b7ce318d48b403b094398f3c0f43fb');
  var srt2 = api.proxy.eth_sendRawTransaction(tx2.serialize().toString('hex'));
  
  srt2.then(function(txID){
    console.log('txID: ' +txID.result);
  });
}
