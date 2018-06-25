
const KeyGenM = require('./KeyGen_v2');
const KeyGenMPC = KeyGenM.KeyGen;

const Consts = require('./consts');
const utils = require('./utils');


const EthereumTx = require('./ethereumjs-tx/index');
const EthereumTx2 = require('./ethereumjs-tx/index2');
var api = require('./ethereumjs-tx/etherscan-api/index').init('CGMFP65SFQTWQ2N6DYWDPKREEVBJIR9T8D','ropsten');
mpcSignParams = keyGenReceiveFunds();
//sendFunds(mpcSignParams);
/*******************************************/

function keyGenReceiveFunds(){
  /*
  const {serverCache,clientCache} = KeyGenMPC();
  const Q1 =  serverCache['q1'];
  const Q2 =  clientCache['q2'];
  const X1 = serverCache['x1'];
  const X2 = clientCache['x2'];
  const Ckey = clientCache['ciphertext'];
  const Q = Q1.mul(X2.toString(Consts.HEX));
  const n = clientCache['paillierPublicKey'].n.toString(Consts.HEX);
  const g = clientCache['paillierPublicKey'].g.toString(Consts.HEX);
  const p = serverCache['keyPair'].privateKey.p.toString(Consts.HEX);
  const q = serverCache['keyPair'].privateKey.q.toString(Consts.HEX);
  const lambda = serverCache['keyPair'].privateKey.lambda.toString(Consts.HEX);
  const preCalculatedDenominator = serverCache['keyPair'].privateKey.preCalculatedDenominator.toString(Consts.HEX);
  
  console.log('Q1x: '+Q1.x.toString('hex'))
  console.log('	')
  console.log('Q1y: '+Q1.y.toString('hex'))
  console.log('	')
  console.log('Q2x: '+Q2.x.toString('hex'))
  console.log('	')
  console.log('Q2y: '+Q2.y.toString('hex'))
  console.log('	')
  console.log('Q: '+ Q.x.toString('hex'))
  console.log('	')
  console.log('Ckey: '+Ckey.toString(Consts.HEX))
  console.log('	')
  console.log('X1: '+X1.toString(Consts.HEX))
  console.log('	')
  console.log('X2: '+X2.toString(Consts.HEX))
  console.log('	')
  console.log('n: '+n)
  console.log('	')
  console.log('g: '+g)
  console.log('	')
  console.log('p: '+p)
  console.log('	')
  console.log('q: '+q)
  console.log('	')
  console.log('lambda: '+ lambda)
  console.log('	')
  console.log('preCalculatedDenominator: '+preCalculatedDenominator)
  */
  const q1x = '2bfe5e6963d0f0ebde3ebaa06e45bee4fa99339443f8ce775ccf7fd5b73b140';
  const q1y = 'd8b8e445dcc3bc92af9b2e18f70a0f3f1f65a4d5a5bfae58c0a8a6fbd7d2911';
  const q2x = '43909d5ec3a3440e3ad9781460a42a45de3df5a084d4c4f511b192073368bd18';
  const q2y = '8c96730893b7a73335976c9570d05c5316e4159462ad4d2463b8252da754937e';
  const Q1 = utils.ec.curve.point(q1x,q1y);
  const Q2 = utils.ec.curve.point(q2x,q2y);
  const Q = '24f9e8ef3ad4e1e885fe1c4cafa471bd694579945ade170f7bca4e46bf67688c';
  const Ckey = '16231587b8c488ce7eec18adbfec5014fa8466fc8b360ab4041d35be9e0afdf1e9da7b0e88b5ea3a15df1a97d48265939781bea5520d611b027bf9f3467b8646538f9c1ba70835369c4a5af1aaa156b4938f3d9f1fb726554aad1057f0bb75e763ec657aeb915dff81b56ea4b6b34a56db287c5c05473252571b592483bb701890ac9830da9e411d3b199a454834b946f261fceee4425d6cab909d5257b49e07b1fb94b11b24b83a7028896217ad15e3e2b33f0926dd5524ca71de79e5b4d5a227b608f864cdb5f4dd02142ada278a23d60d2d9fc5cf68ae01bfcc2271fc7748490243747071747091240fbadd2ab78c397814c8aad78d7c5a147c731e1a506';
  const X1 = '22916b96f484fe8e24876fd707e6d9c6405cb0bd315acb6ec5b9997be91045c7';
  const X2 = '853f15afa668be7c6fda5c9400f165c73b4dcaa38e6f8d0519eb32389af532f0';
  const n = '1f79d0813668c6e5dc1719d9152ca2f8d46e165ed5483b28432b4fe8d77312378975a9de35b744bf974416e4f0221f71b63af168795eeb7a3404cacc9882a8eb455feb949943d236e365db67f27600ad33a436bb4a69cf5ad5ae0f1b10e10f667a84b63057a184747da10afb062a6f2f016af35ea7597747a88dea8de0ecaf75';
  const g = '3257e39569734231672f59071663ed59c6ceda71fada27f50ae3eafe44f8701d8085e42cf41f0e3bac6ef6be9c56454a380d4c2ecb6ec58dc496cfb3252e4c1ed9adfabee49521aa90eee60f81596819ff0b64a6e0e747fc97276153def11d08712c378f029f8321d3683600dd9651a0fb56ac505410623e68bc51eb28d2fd433';
  const p ='6aaf6ba8460d414bc74edeaea395c89e59728392147950d1a2a9dc656d04c008d723bb7993c87ad6cc2a2da6055f2592cd5b455806f0ba4ea6065089ac9ec60f';
  const q ='4b87637b1af329bb53baf1ee5e9925ba6dbe1e199ad5a19a143b7d6473ed0f67959d82f1304859f95c01735f384b8a6c1f6646a0991e6aa4ed8cb716cd74563b';
  const lambda = '53ef8158911767ba4ae844ed8dcc5d42367ae65238c09dc0b31e2a6ce932db3ec3e46fa5e49361fee8b59262805afe84909d2e6bee5273f08ab7722196b1c2717dc2f68340b3bdd4c0f5721d2b6830e1213438299d9cf7d2fcc1e3832a7dffe57a093f64342c7f0b8e8e6fe4c154a880371913babe1b86358d47b2791244332';
  const preCalculatedDenominator = '1ce904a385926580fe7b1ea718494aefb4b89e4d2d3a1f7bc77c7fda0e86c66804452b1d5e9774dd16f8e44ac0ba6c7e0dd2c3a0164a422b3a55909b1fd68ac0f6b6c246b062d211d78149f3be91fa6eed6f3784546cdd8e8e588916ae43bc4947fb58ceed333dbfaec06845dc2facd79426cb6e0ded66b3ff5e29c627e4544a';
  
  const mpcSignParams = {Q1:Q1,Q2:Q2,Q:Q,Ckey:Ckey,X1:X1,X2:X2,n:n,g:g,p:p,q:q,lambda:lambda,preCalculatedDenominator:preCalculatedDenominator};
  
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
  console.log('Address: '+ addressEth)

//  We first need to create a smart contract for erc20 and an ICO smart contract.
// I use the simple guide: https://erc20token.sonnguyen.ws/en/latest/
  // send money to addressEth
  const tokenAdd = "0xed586810359961be8b26679b03e16bca65a50fca";
  const icoAdd = "0x7e3c8228ff2c93d1bee2aa36aece699ce314334b"; //not used in code, use manually 

//In order to get tokens we need to send Eth to the ICO address. 
//Using myetherwallet access to metamask we can make transfers of ethers and tokens.



  var fs    = require("fs");
  var Web3 = require('web3');
//var web3 = new Web3(new Web3("http://localhost:8545"));
  var web3 = new Web3(new Web3.providers.HttpProvider("https://ropsten.infura.io/ "));
  var count = web3.eth.getTransactionCount("0xe9f44b58fc2080e650e0a24b89c7ef1914ce745a");
var abiArray = JSON.parse(fs.readFileSync('mycoin.json', 'utf-8'));
var contractAddress = tokenAdd;
var contract = web3.eth.contract(abiArray).at(contractAddress);


  console.log('Address: '+ addressEth)
//https://ethereum.stackexchange.com/questions/24828/how-to-send-erc20-token-using-web3-api   
  const txParams2 = {
    from: "0xe9f44b58fc2080e650e0a24b89c7ef1914ce745a",
    nonce: web3.toHex(count),
    gasPrice: '0x4a817c800', 
    gasLimit: '0x9318',
    to: contractAddress,
    value: '0x0', 
    data: contract.transfer.getData("0xAC6a7e41D8c6843A5da794bf018abE428034A996", 19, {from: "0xe9f44b58fc2080e650e0a24b89c7ef1914ce745a"}),
    // EIP 155 chainId - mainnet: 1, ropsten: 3
    chainId: 3
  }

  const tx2 = new EthereumTx2(txParams2);
   tx2.sign2(mpcSignParams,addressEth)
  //console.log(tx.serialize().toString('hex'))
 
  
  serializedTx2 = tx2.serialize().toString('hex');
  //var balance = api.account.balance('0xf111b4d5a8b7ce318d48b403b094398f3c0f43fb');
  var srt2 = api.proxy.eth_sendRawTransaction(tx2.serialize().toString('hex'));
  
  srt2.then(function(txID){
    console.log('txID: ' +txID.result);
  });

/*
web3.eth.sendRawTransaction('0x' + tx2.serialize().toString('hex'), function(err, hash) {
    if (!err)
        console.log(hash);
    else
        console.log(err);
});
*/

}

