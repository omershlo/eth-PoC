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
  
/*
  const q1x = '5aa1053ded3f3f53c2b857f934cd78f1e8ed9017284f30fc881509c168044be6';
  const q1y = '9c26406735f6b5586d417ea015729d5ccb579ab4533c9d5486a817fab6a6a71';
  const q2x = '7294c18b08c44f0d57730f8a2c48b82dfa1d93573c6ea5a9740b5cfb5d66739e';
  const q2y = '5590ae2350d7e639688eb0e5acbd7c23f25c18c607fc0a17b08f100081e858a4';
  const Q1 = utils.ec.curve.point(q1x,q1y);
  const Q2 = utils.ec.curve.point(q2x,q2y);
  const Q = '2e76a0a5c9d42f106882467132e2458f0c127a6c428c7ac5e110984497fdebb5';
  const Ckey = 'cc6edf2dc260e71f3f07f48251549ce1642bd4d9f240c0c32adc0a692a8050f72ea43da02323957661cb1c90c9124b26dab13a0c0d7ef34935d151ea41e9ab64604fc5856138818ff3f7f62619c945f80a74101e7d8918b661f56904a63b6a4bbe784fddd3771c21f9dcdb567afc4ad6c8c9df2150e48b3374edd4553ad3b273f82c9f39ffc20baf6be38eeea91ac0eba8755da4ccfc791848a9b68b1ef79a53b6bf4daeb30e4106d2c9784d49189bb362409f972f27b01a58088512f37cbbbec9808a302b5b89d7edd21d79d076b1567fcfcffe7610c7adedc35623b0900079ac8020eda19c786ea72c1c426746c07851cb25566c75a29463a152f852f4b27';
  const X1 = '6a5c5e1fed37f90a91d216bb8d48ef51a34c142ede272a8a112f1baba4731185';
  const X2 = '98bdefffc1f4fc54680b5e76e5fc56a06436afc2fa35284e88548ed478878bff';
  const n = '6f8e8cf01da15d7d13c1585cb52768d09ee2755d750794b72bc3e4880337bbffd9e1095a5fca35b655d3b5f6bb66cea35a174a8b6f9c27eae626a32871869cc2c5aaee03ca7a0ca9c00b7c5611391415c689dfdeac9222e3e76fc3d11ddcafd71045baa151d7ae03b9ddcf5e44353538ae21a1c5ae3173291ff73497b3d4b477';
  const g = '3a016ece58aa6ef5829ff669e37eb1164793ee40bfd3aeb1e0cc3e8fb2905fab10654ac55fc3fc29426ae827ce708df476a2d8263c55e1d5d226124df51bad0fb444df68586fc33faf156fd5ddd3244b8770eba9c36c2b38c936868fdc7b0a9dd182c8626e8087c2ca23601e1453d431fce0c8524263db518af251e819e0684e6';
  const p ='17681a4ed3bff3bacc837b06b89ba547edbda96a34e06132224f3a46d5438d272fc6950e42eaf83f3a5616ed97f4a0a4d6962f6ad818170df3206bf540f738953';
  const q ='4c41aa3f612c81db4b85ebdb56cf541a678169867a5f1eb0047be61e25012c19d85363d5126fa5502d2b775b633d039bee75a0c4969ed6088f4dece262d0afcd';
  const lambda = '1039f892a2907d4eb3bf0832b89aad80171c48ed030f10fa0facc8cdf728b04a73792b405867e2938a281a77ab8ca0623ba64c01a9d58cc9bb139567a0cdc304cd38f685b2cee19e7f7661c10bbc6cb9acae3c776701e1e6a745d9c8f75d7b88785e67425636c42e880bc4d2d1b2ee71f09f91cafe8e225d4a462fc3ac721b4';
  const preCalculatedDenominator = '66bf759c667ae7f003541edc5d902ea48a48c400c25cd68c1a7d1fc4c7d5e5aad53fa286ab53257215dd9f1d8ffb62f3b8ea6e12b98678780007189b29fbd27fd504c3170a2954ae80b4fcd587a3895853281d8300d36b905276afaa1469f8ccc10c0ce0b3a7176b9985fbd916adaf93f5b1c4754ccf8ce4d396aa3d21adf5e9';
  const mpcSignParams = {Q1:Q1,Q2:Q2,Q:Q,Ckey:Ckey,X1:X1,X2:X2,n:n,g:g,p:p,q:q,lambda:lambda,preCalculatedDenominator:preCalculatedDenominator};
  */

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
  web3.eth.sendRawTransaction('0x' + serializedTx ,function(err, hash) {
  if (!err)
    console.log("MPC receiving: " + hash); 
  console.log("awaiting confirmation...");
});

  setTimeout(sendFunds,100000,mpcSignParams);
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
    var count = web3.eth.getTransactionCount('0x'+addressEth);
    console.log("nonce: "+ web3.toHex(count))
  const txParams2 = {
    nonce: web3.toHex(count),
    gasPrice: '0x4a817c800', 
    gasLimit: '0x5308',
    to: '0x112e1304260Dee1504B75721fe0a2dFB3aFe71e7', 
    //to: '0xAC6a7e41D8c6843A5da794bf018abE428034A996', 
  //  value: '0x5af3107a40000', 
    value: '0x0', 
    data: '0x0',
    // EIP 155 chainId - mainnet: 1, ropsten: 3
    chainId: 3
  }
  var api = require('./ethereumjs-tx/etherscan-api/index').init('CGMFP65SFQTWQ2N6DYWDPKREEVBJIR9T8D','ropsten');

  const tx2 = new EthereumTx2(txParams2);
  tx2.sign2(mpcSignParams,addressEth)
  console.log(tx2)
  console.log(tx2.serialize().toString('hex'))
  serializedTx2 = tx2.serialize().toString('hex');
  //var balance = api.account.balance('0xf111b4d5a8b7ce318d48b403b094398f3c0f43fb');
  //var srt2 = api.proxy.eth_sendRawTransaction(tx2.serialize().toString('hex'));
  web3.eth.sendRawTransaction('0x' + tx2.serialize().toString('hex') ,function(err, hash) {
  if (!err)
    console.log("MPC sending: " + hash); 
});
  
 // srt2.then(function(txID){
 //   const txid_hash = txID.result;
 //   console.log('txID: ' +txid_hash);
    
 // });
 // setTimeout(track_tx,100000,txid_hash);

}
