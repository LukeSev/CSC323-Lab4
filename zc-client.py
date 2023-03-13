import sys, time, json, os, hashlib, random
from Crypto.Cipher import AES 
from Crypto.Cipher import Random
from ecdsa import VerifyingKey, SigningKey
from p2pnetwork.node import Node

SERVER_ADDR = "zachcoin.net"
SERVER_PORT = 9067

class ZachCoinClient (Node):
    
    #ZachCoin Constants
    # (Message Types)
    BLOCK = 0
    TRANSACTION = 1
    BLOCKCHAIN = 2
    UTXPOOL = 3
    # (Mining constants)
    COINBASE = 50
    DIFFICULTY = 0x000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    #Hardcoded gensis block
    blockchain = [
        {
            "type": BLOCK,
            "id": "124059f656eb6b016ce36583b5d6e9fdaf82420355454a4e436f4ee2ff17dba7",
            "nonce": "5052bfab11df236c43a4d877d93e42a3",
            "pow": "000000be01b9e4b6fdd73985083174007c30a98dc0801eaa830e27bbbea0d705",
            "prev": "124059f656eb6b016ce36583b5d6e9fdaf82420355454a4e436f4ee2ff17dba7",
            "tx": {
                "type": TRANSACTION,
                "input": {
                    "id": "0000000000000000000000000000000000000000000000000000000000000000",
                    "n": 0
                },
                "sig": "33399ed9ba1cc40eb1395ef8826955398446badb9c7c84113d545806714809a013c73d71b3326041853638b1190443af",
                "output": [
                    {
                        "value": 50,
                        "pub_key": "c26cfef538dd15b6f52593262403de16fa2dc7acb21284d71bf0a28f5792581b4a6be89d2a7ec1d4f7849832fe7b4daa"
                    }
                ]
            }
        }
    ]
    utx = []
  
    def __init__(self, host, port, id=None, callback=None, max_connections=0):
        super(ZachCoinClient, self).__init__(host, port, id, callback, max_connections)

    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)
        
    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)

    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)

    def node_message(self, connected_node, data):
        print("node_message from " + connected_node.id + ": " + json.dumps(data,indent=2))

        if data != None:
            if 'type' in data:
                if data['type'] == self.TRANSACTION:
                    self.utx.append(data)
                elif data['type'] == self.BLOCKCHAIN:
                    self.blockchain = data['blockchain']
                elif data['type'] == self.UTXPOOL:
                    self.utx = data['utxpool']
                elif data['type'] == self.BLOCK:
                    # Validate block
                    if(self.validate_block(data) == 0):
                        print("INVALID BLOCK")
                        return
                    # If valid, add to end of blockchain
                    self.blockchain.append(data)
                #TODO: Validate blocks

    def node_disconnect_with_outbound_node(self, connected_node):
        print("node wants to disconnect with oher outbound node: " + connected_node.id)
        
    def node_request_to_stop(self):
        print("node is requested to stop!")

    def validate_block(self, block):
        # First check that all required fields are present
        fields = ["type", "id", "nonce", "pow", "prev", "tx"]
        invalid_msg = "INVALID BLOCK: "
        for field in fields:
            if field not in block:
                print(invalid_msg + " Missing Fields")
                return 0
        
        # Make sure type is BLOCK
        if(block["type"] != self.BLOCK):
            print(invalid_msg + " Type is not BLOCK")
            return 0
        
        # Verify block ID
        if(compute_BlockID(block) != block["id"]):
            print(invalid_msg + " Invalid Block ID")
            return 0
        
        # Verify prev block is at the top of the blockchain
        if(self.blockchain[len(self.blockchain)-1]["id"] != block["prev"]):
            print(invalid_msg + " Invalid Previous Block")
            return 0
        
        # Verify Proof of Work
        pow = compute_PoW(block["tx"], block["nonce"])
        if(int(pow, 16) >= self.DIFFICULTY):
            print(invalid_msg + " Incorrect PoW")
            return 0
        
        # Validate Transaction
        if(self.validate_tx(block["tx"] == 0)):
            print(invalid_msg + " Invalid Transaction")
            return 0
        
        # If you got this far, block is valid and should be added to blockchain

    def validate_tx(self, tx):
        # First check that all required fields are present
        fields = ["type", "input", "sig", "output"]
        invalid_msg = "INVALID TRANSACTION: "
        for field in fields:
            if field not in fields:
                print(invalid_msg + " Missing Fields")
                return 0
            
        # Check that type is TRANSACTION
        if(tx["type"] != self.TRANSACTION):
            print(invalid_msg + " Type is not TRANSACTION")
            return 0
        
        # Check transaction input
        tx_input = tx["input"]
        if((tx_input["n"] > len(self.blockchain)-1) or (self.blockchain[tx_input["n"]]["id"] != tx_input["id"])):
            print(invalid_msg + " Invalid Input")
            return 0
        
        # Check that input is unspent
        input_id = tx_input["id"]
        for block in self.blockchain:
            if(block["input"]["id"] == input_id):
                print(invalid_msg + " Input already spent")
                return 0
            
        # Check that value of input = sum of outputs (excluding coinbase)
        output = tx["output"]
        input_sum = self.blockchain[tx_input["n"]]["output"][0]["value"]
        if(len(output) < 2):
            print(invalid_msg + " Not enough outputs")
            return 0
        if(len(output) == 2):
            # Check sums
            if(output[0]["value"] != input_sum):
                print(invalid_msg + " Input and Outputs don't match")
                return 0

            # Check if coinbase value valid
            if(output[1]["value"] != self.COINBASE):
                print(invalid_msg + "Invalid Coinbase value")
                return 0
        elif(len(output) == 3):
            output_sum = output[0]["value"] + output[1]["value"]
            if(output_sum != input_sum):
                print(invalid_msg + " Input and Outputs don't match")
                return 0
            if(output[2]["value"] != self.COINBASE):
                print(invalid_msg + "Invalid Coinbase value")
                return 0
        else:
            print(invalid_msg + " Too many outputs")
            return 0
        
        # Verify signature of transaction
        vk = VerifyingKey.from_string(bytes.fromhex(tx["sig"]))
        try:
            assert vk.verify(tx["sig"], json.dumps(tx['input']))
        except Exception:
            print(invalid_msg + "Bad Signature")

        return 1
    

    def find_block(self, block_id):
        # Given block id as string, see if block exists in the blockchain and return its location
        for i in range(len(self.blockchain)):
            if(self.blockchain[i]["id"] == block_id):
                return i
        return -1

    def create_utx(self, vk, block_id, amt, pubkey, sk):
        # Given block ID for input, amount to send and public key of recipient, create transaction
        # Check if input block actually exists
        input_ind = self.find_block(block_id)
        if(input_ind == -1):
            print("Input block doesn't exist, exiting")
            return 0
        
        input_field = {
            'id': block_id,
            'n': input_ind
        }
        
        sig = sk.sign(json.dumps(input_field, sort_keys=True).encode('utf-8')).hex()


        utx = {
            'type': self.TRANSACTION,
            'input': input_field,
            'sig': sig,
            'output': []
        }

        payout = {
            'value' : amt,
            'pub_key' : pubkey
        }
        utx['output'].append(payout)

        # blk = self.blockchain[input_ind]
        # outpt = blk["output"]
        input_pay = self.blockchain[input_ind]["tx"]["output"][0]["value"]
        if(input_pay > amt):
            change = input_pay - amt
            payback = {
                'value' : change,
                'pub_key' : vk.to_string().hex()
            }
            utx['output'].append(payback)

        return utx


    def mine_utx(self, utx, vk):
        # Given unspent transaction, validate it and attempt to mine with PoW
        if(self.validate_tx(utx) == 0):
            print("INVALID UTX. MINING FAILED. RIP")
            return 0
        
        # Start building block
        

        # Add coinbase to utx before processing
        coinbase = {
            'value': self.COINBASE,
            'pub_key': vk.to_string().hex()
        }
        utx['output'].append(coinbase)

        # Find PoW
        nonce = Random.new().read(AES.block_size).hex()
        while( int( hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + nonce.encode('utf-8')).hexdigest(), 16) > self.DIFFICULTY):
            nonce = Random.new().read(AES.block_size).hex()
        pow = hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + nonce.encode('utf-8')).hexdigest()

        return ()

    
def compute_BlockID(block):
    return hashlib.sha256(json.dumps(block['tx'], sort_keys=True).encode('utf-8')).hexdigest()

def compute_PoW(tx, nonce):
    return hashlib.sha256(json.dumps(tx, sort_keys=True).encode('utf-8') + nonce.encode('utf-8')).hexdigest()

def main():

    if len(sys.argv) < 3:
        print("Usage: python3", sys.argv[0], "CLIENTNAME PORT")
        quit()

    #Load keys, or create them if they do not yet exist
    keypath = './' + sys.argv[1] + '.key'
    if not os.path.exists(keypath):
        sk = SigningKey.generate()
        vk = sk.verifying_key
        with open(keypath, 'w') as f:
            f.write(sk.to_string().hex())
            f.close()
    else:
        with open(keypath) as f:
            try:
                sk = SigningKey.from_string(bytes.fromhex(f.read()))
                vk = sk.verifying_key
            except Exception as e:
                print("Couldn't read key file", e)

    #Create a client object
    client = ZachCoinClient("127.0.0.1", int(sys.argv[2]), sys.argv[1])
    client.debug = False

    #time.sleep(1)

    client.start()

    #time.sleep(1)

    #Connect to server 
    client.connect_with_node(SERVER_ADDR, SERVER_PORT)
    print("Starting ZachCoin™ Client:", sys.argv[1])
    #time.sleep(2)

    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        slogan = " You can't spell \"It's a Ponzi scheme!\" without \"ZachCoin\" "
        print("=" * (int(len(slogan)/2) - int(len(' ZachCoin™')/2)), 'ZachCoin™', "=" * (int(len(slogan)/2) - int(len('ZachCoin™ ')/2)))
        print(slogan)
        print("=" * len(slogan),'\n')

        print(client.id)
        print(client.callback)

        x = input("\t0: Print keys\n\t1: Print blockchain\n\t2: Print UTX pool\n\t3: Create transaction\n\t4: Mine transaction\n\nEnter your choice -> ")
        try:
            x = int(x)
        except:
            print("Error: Invalid menu option.")
            input()
            continue
        if x == 0:
            print("sk: ", sk.to_string().hex())
            print("vk: ", vk.to_string().hex())
        elif x == 1:
            print(json.dumps(client.blockchain, indent=1))
        elif x == 2:
            print(json.dumps(client.utx, indent=1))
        elif x == 3:
            pk = input("What is the public key of who you want to pay?\tEnter Here -> ")
            block_id = input("Which block would you like to pay from?\tEnter Here -> ")
            amt = input("How much do you want to pay?\t\t\tEnter Here ->")
            utx = client.create_utx(vk, block_id, int(amt), pk, sk)
            client.node_message(client, utx)

        # TODO: Add options for creating and mining transactions
        # as well as any other additional features

        input()
        
if __name__ == "__main__":
    main()