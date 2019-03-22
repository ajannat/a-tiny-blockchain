const sha256 = require("crypto-js/sha256");
const EC = require("elliptic").ec;
var ec = new EC("secp256k1");

class Block{
    constructor(timestamp, transactions, previousHash = ""){
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.hash = this.calcualteHash();
        this.nonce = 0;
    }

    mineBlock(difficulty){
        while(this.hash.substring(0, difficulty) !== Array(difficulty+1).join("0")){
            this.nonce++;
            this.hash = this.calcualteHash();
        }
        console.log("Mining done : "+this.hash);
    }

    calcualteHash(){
        return sha256(
            this.timestamp + JSON.stringify(this.transactions) + this.previousHash+this.nonce
            ).toString();
    }

    hasValidTransactions(){
        for(const tx of this.transactions){
            if(!tx.isValid())
                return false;
        }
        return true;
    }
}

class Transaction{
    constructor(fromAddress, toAddress, amount){
        this.fromAddress = fromAddress;
        this.toAddress = toAddress;
        this.amount = amount;
    }

    calcualteHash(){
        return sha256(this.fromAddress+this.toAddress+this.amount).toString();
    }

    signTransaction(key){
        if(key.getPublic("hex") !== this.fromAddress)
            throw new Error("You do not have access");
        const hashTx = this.calcualteHash();
        const signature = key.sign(hashTx, "base64");
        this.signature = signature.toDER();
    }

    isValid(){
        if(this.fromAddress === null) true;
        if(!this.signature || this.signature.length === 0)
            throw new Error("No signature found.");
        
        const key = ec.keyFromPublic(this.fromAddress, "hex");
        return key.verify(this.calcualteHash(), this.signature);
    }
}

class Blockchain{
    constructor(){
        this.chain = [this.genesisBlock()];
        this.difficulty = 3;
        this.pendingTansactions = [];
        this.miningReward = 50;
    }

    genesisBlock(){
        return new Block("2019-01-01", "GENESIS", "0000");
    }

    getLatestBlock(){
        return this.chain[this.chain.length-1];
    }

    addTransaction(transaction){
        if(!transaction.fromAddress || !transaction.toAddress)
            throw new Error("Cannot process transaction");
        
        if(!transaction.isValid())
            throw new Error("Invalid transaction");
        
        if(transaction.amount < 0)
            throw new Error("Invalid transaction amount");

        // if(transaction.amount > this.getBalanceOfAddress(transaction.fromAddress))
        //     throw new Error("Not enough balance");

        this.pendingTansactions.push(transaction);
    }

    minePendingTransactions(minerAddress){
        let block = new Block(Date.now(), this.pendingTansactions);
        block.mineBlock(this.difficulty);
        this.chain.push(block);
        this.pendingTansactions = [
            new Transaction(null, minerAddress, this.miningReward)
        ];
    }

    isBlockchainValid(){
        for(let i = 1; i < this.chain.length; i++){
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i-1];

            if(currentBlock.hash !== currentBlock.calcualteHash()){
                return false;
            }

            if(currentBlock.previousHash !== previousBlock.hash){
                return false;
            }

            if(!currentBlock.hasValidTransactions())
                return false;
        }
        return true;
    }

    getBalanceOfAddress(address){
        let balance = 0;
        for(const block of this.chain){
            for(const trans of block.transactions){
                if(trans.fromAddress === address){
                    balance-=trans.amount;
                }
                if(trans.toAddress === address){
                    balance+=trans.amount;
                }
            }
        }
        return balance;
    }
}

module.exports = {
    Block,
    Transaction,
    Blockchain
}
