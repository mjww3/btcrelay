import json
from web3 import Web3,HTTPProvider
from web3.providers import (
    BaseProvider,
)
from web3.exceptions import (
    BadFunctionCallOutput,
)
import hashlib, struct

import logging
import requests
import time

import logging
logger = logging.getLogger('myapp')
hdlr = logging.FileHandler('myapp.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)


class StoreBlocks(object):
	def __init__(self,providerString):
		self.providerString = providerString

	def connect(self):
		self.provider = HTTPProvider(self.providerString)
		self.web3 = Web3(self.provider)

	def returnAccounts(self):
		print (self.web3.eth.accounts)
		return self.web3.eth.accounts

	def getLastBlockHeight(self):
		self.lastBlock = self.btcrelay.call().getLastBlockHeight()
		return self.lastBlock

	def fetchApi(self):
		lastBlock = self.btcrelay.call().getLastBlockHeight()
		self.newBlock = str(int(lastBlock)+1)
		print "new block "+self.newBlock
		#self.newBlock = "400001"
		##reply = requests.get("http://insight.coinbank.info/insight-api/block-index/"+self.newBlock)
		while(True):
			time.sleep(50)
			reply = requests.get("https://test-insight.bitpay.com/api/block-index/"+self.newBlock)
			#print reply.status_code
			#print type(reply.status_code)
			if reply.status_code==200:
				self.jsonHash = reply.json()
				self.blockHash = self.jsonHash['blockHash']
				print self.blockHash
				##rep= requests.get("http://insight.coinbank.info/insight-api/block/"+self.blockHash)
				rep= requests.get("https://test-insight.bitpay.com/api/rawblock/"+self.blockHash)
				self.json = rep.json()
				break
			else:
				print ("block not mined yet...............wait")
		
	def connectBTCRelay(self,address):
		self.abi = json.loads('[{"constant": false, "type": "function", "name": "bulkStoreHeader", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "bytes", "name": "headersBytes"}, {"type": "int256", "name": "count"}]}, {"constant": false, "type": "function", "name": "changeFeeRecipient", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "blockHash"}, {"type": "int256", "name": "feeWei"}, {"type": "int256", "name": "feeRecipient"}]}, {"constant": false, "type": "function", "name": "computeMerkle", "outputs": [{"type": "uint256", "name": "out"}], "inputs": [{"type": "int256", "name": "txHash"}, {"type": "int256", "name": "txIndex"}, {"type": "int256[]", "name": "sibling"}]}, {"constant": false, "type": "function", "name": "depthCheck", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "n"}]}, {"constant": false, "type": "function", "name": "feePaid", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "txBlockHash"}, {"type": "int256", "name": "amountWei"}]}, {"constant": false, "type": "function", "name": "getAverageChainWork", "outputs": [{"type": "int256", "name": "out"}], "inputs": []}, {"constant": false, "type": "function", "name": "getBlockHeader", "outputs": [{"type": "bytes", "name": "out"}], "inputs": [{"type": "int256", "name": "blockHash"}]}, {"constant": false, "type": "function", "name": "getBlockchainHead", "outputs": [{"type": "int256", "name": "out"}], "inputs": []}, {"constant": false, "type": "function", "name": "getChainWork", "outputs": [{"type": "int256", "name": "out"}], "inputs": []}, {"constant": false, "type": "function", "name": "getChangeRecipientFee", "outputs": [{"type": "int256", "name": "out"}], "inputs": []}, {"constant": false, "type": "function", "name": "getFeeAmount", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "blockHash"}]}, {"constant": false, "type": "function", "name": "getFeeRecipient", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "blockHash"}]}, {"constant": false, "type": "function", "name": "getLastBlockHeight", "outputs": [{"type": "int256", "name": "out"}], "inputs": []}, {"constant": false, "type": "function", "name": "helperVerifyHash__", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "uint256", "name": "txHash"}, {"type": "int256", "name": "txIndex"}, {"type": "int256[]", "name": "sibling"}, {"type": "int256", "name": "txBlockHash"}]}, {"constant": false, "type": "function", "name": "priv_fastGetBlockHash__", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "blockHeight"}]}, {"constant": false, "type": "function", "name": "priv_inMainChain__", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "txBlockHash"}]}, {"constant": false, "type": "function", "name": "relayTx(bytes,int256,int256[],int256,int256)", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "bytes", "name": "txBytes"}, {"type": "int256", "name": "txIndex"}, {"type": "int256[]", "name": "sibling"}, {"type": "int256", "name": "txBlockHash"}, {"type": "int256", "name": "contract"}]}, {"constant": false, "type": "function", "name": "setInitialParent", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "blockHash"}, {"type": "int256", "name": "height"}, {"type": "int256", "name": "chainWork"}]}, {"constant": false, "type": "function", "name": "storeBlockHeader", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "bytes", "name": "blockHeaderBytes"}]}, {"constant": false, "type": "function", "name": "storeBlockWithFee(bytes,int256)", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "bytes", "name": "blockHeaderBytes"}, {"type": "int256", "name": "feeWei"}]}, {"constant": false, "type": "function", "name": "storeBlockWithFeeAndRecipient(bytes,int256,int256)", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "bytes", "name": "blockHeaderBytes"}, {"type": "int256", "name": "feeWei"}, {"type": "int256", "name": "feeRecipient"}]}, {"constant": false, "type": "function", "name": "verifyTx", "outputs": [{"type": "uint256", "name": "out"}], "inputs": [{"type": "bytes", "name": "txBytes"}, {"type": "int256", "name": "txIndex"}, {"type": "int256[]", "name": "sibling"}, {"type": "int256", "name": "txBlockHash"}]}, {"constant": false, "type": "function", "name": "within6Confirms", "outputs": [{"type": "int256", "name": "out"}], "inputs": [{"type": "int256", "name": "txBlockHash"}]}, {"inputs": [{"indexed": true, "type": "int256", "name": "recipient"}, {"indexed": false, "type": "int256", "name": "amount"}], "type": "event", "name": "EthPayment(int256,int256)"}, {"inputs": [{"indexed": true, "type": "uint256", "name": "blockHash"}, {"indexed": true, "type": "int256", "name": "returnCode"}], "type": "event", "name": "GetHeader(uint256,int256)"}, {"inputs": [{"indexed": true, "type": "uint256", "name": "txHash"}, {"indexed": true, "type": "int256", "name": "returnCode"}], "type": "event", "name": "RelayTransaction(uint256,int256)"}, {"inputs": [{"indexed": true, "type": "uint256", "name": "blockHash"}, {"indexed": true, "type": "int256", "name": "returnCode"}], "type": "event", "name": "StoreHeader(uint256,int256)"}, {"inputs": [{"indexed": true, "type": "uint256", "name": "txHash"}, {"indexed": true, "type": "int256", "name": "returnCode"}], "type": "event", "name": "VerifyTransaction(uint256,int256)"}]')
		self.address = address
		self.btcrelay = self.web3.eth.contract(self.abi,self.address)
		print (self.btcrelay)

	def setInitialParent(self):
		contr = self.btcrelay.transact({"from":"0xcc80bd4c81bd5d436e6646eb65872c26a7e89bbd","gas":4500000}).setInitialParent(int("00000000b1023ec79d9591cd21498b50800b1669b5a9761b9724651c85a231a9",16),1210122,1)
		print (contr)

	def storeBlockHeader(self):
		print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%5"
		print self.headers
		print self.btcrelay.call().storeBlockHeader(self.headers.decode('hex'))
		self.btcrelay.transact({"from":"0xcc80bd4c81bd5d436e6646eb65872c26a7e89bbd"}).storeBlockHeader(self.headers.decode('hex'))

	def setParams(self):
		#self.version = self.json['version']
		#self.previous_hash  = self.json['previousblockhash']
		#self.merkel_root = self.json['merkleroot']
		#self.time = self.json['time']
		#self.bits = hex(self.json['bits'])
		#self.nonce = self.json['nonce']
		#self.bits = self.bits[2::]
		#print self.bits
		#print type(self.bits)
		#print type(self.time)
		#print self.json
		self.headers = self.json['rawblock'][0:160]
		print self.headers
	def returnHeader(self):
		self.version_le = struct.pack("<L",int(self.version))
		self.previous_hash_le = self.previous_hash.decode("hex")[::-1]
		self.merkel_root_le = self.merkel_root.decode("hex")[::-1]
		self.final_all_le = struct.pack("<LLL", self.time, int(self.bits,16), self.nonce)
		self.header = self.version_le+self.previous_hash_le+self.merkel_root_le+self.final_all_le

	def verifyBlockhash(self):
		self.hash = hashlib.sha256(hashlib.sha256(self.headers.decode('hex')).digest()).digest()
		self.hashval = self.hash[::-1].encode('hex')
		print (self.hashval)

	def isBlockHashVerified(self):
		if (self.hashval==self.blockHash):
			return True
		else:
			return False

	def getwithin6(self):
		return self.btcrelay.call().within6Confirms("88c286dcc479e6fe0aa1dec85e67a8294d238628c581ae60de300977a7a7ef2a")

if __name__ == "__main__":
	storeblock = StoreBlocks("http://128.199.186.255:8545")
	storeblock.connect()
	storeblock.connectBTCRelay("0x79ff44094598fcfae1206bf612cd1de2544701ce")
	while True:
		if(int(storeblock.getLastBlockHeight())>0):
			f =  (storeblock.getLastBlockHeight())
			print f
			print ("::::::::::::::::::::::::::::::::::::")
			#storeblock.getwithin6()
			print "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
			storeblock.fetchApi()
			storeblock.setParams()
			#storeblock.returnHeader()
			storeblock.verifyBlockhash()
			if (storeblock.isBlockHashVerified()):
				storeblock.storeBlockHeader()
				logger.info("stored  "+str(f))
				time.sleep(40)
			else:
				print "not ok"
		else:
			storeblock.setInitialParent()
			time.sleep(100)

