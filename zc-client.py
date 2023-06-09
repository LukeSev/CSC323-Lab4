import sys, time, json, os, hashlib, random
from Crypto.Cipher import AES 
from Crypto import Random
from ecdsa import VerifyingKey, SigningKey
from p2pnetwork.node import Node
import signal

SERVER_ADDR = "zachcoin.net"
SERVER_PORT = 9067

# Handles disconnecting from server
class DisconnectHandler:
    def __init__(self, node):
        self.client = node
    def __call__(self, signo, frame):
        self.client.stop()

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
        #print("node_message from " + connected_node.id + ": " + json.dumps(data,indent=2))
        print("node_message from " + connected_node.id)

        if data != None:
            if 'type' in data:
                if data['type'] == self.TRANSACTION:
                    print("Type - UTX:\n" + json.dumps(data,indent=2))
                    self.utx.append(data)
                    print(json.dumps(data,indent=2))
                elif data['type'] == self.BLOCKCHAIN:
                    print("Type - BLOCKCHAIN:\n" + json.dumps(data,indent=2))
                    self.blockchain = data['blockchain']
                    print_blockchain(data['blockchain'])
                elif data['type'] == self.UTXPOOL:
                    # print("Type - UTXPOOL:\n" + json.dumps(data,indent=2))
                    print("Type - UTXPOOL:\n")
                    self.utx = data['utxpool']
                    self.print_utxpool()
                elif data['type'] == self.BLOCK:
                    print("Type - BLOCK:\n" + json.dumps(data,indent=2))
                    # Validate block
                    try:
                        if(self.validate_block(data) == 0):
                            print("INVALID BLOCK")
                            return
                    except Exception:
                        print("MALFORMED BLOCK")
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
        if(self.validate_tx(block["tx"], 1) == 0):
            print(invalid_msg + " Invalid Transaction")
            return 0
        
        # If you got this far, block is valid and should be added to blockchain
        return 1

    def validate_tx(self, tx, cb):
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
        input_block = self.find_block(tx_input["id"])
        if(input_block is None):
            print(invalid_msg + " Input doesn't exist")
            return 0
        
        # Check that input is unspent
        input_id = tx_input["id"]
        n = tx_input["n"]
        for block in self.blockchain:
            if((block["tx"]["input"]["id"] == input_id) and (len(block["tx"]["input"]) > n) and (block["tx"]["input"]["n"] == n)):
                print(invalid_msg + " Input already spent")
                return 0
            
        # Check that value of input = sum of outputs (excluding coinbase)
        output = tx["output"]
        input_sum = input_block["tx"]["output"][n]["value"]
        if(len(output) < 1):
            print(invalid_msg + " No outputs")
            return 0
        if(len(output) == 1):
            # Check sums
            if((cb == 1) or (output[0]["value"] != input_sum)):
                print(invalid_msg + " Input and Outputs don't match or missing coinbase")
                return 0
        elif(len(output) == 2):
            if(cb == 1):
                output_sum = output[0]["value"]
            else:
                output_sum = output[0]["value"] + output[1]["value"]
            if(output_sum != input_sum):
                print(invalid_msg + " Input and Outputs don't match")
                return 0
        elif(len(output) == 3):
            if(cb != 1):
                print(invalid_msg + " Coinbase required")
                return 0
            output_sum = output[0]["value"] + output[1]["value"]
            if(output_sum != input_sum):
                print(invalid_msg + " Inputs and Outputs don't match")
        else:
            print(invalid_msg + " Too many outputs")
            return 0
        
        # Verify signature of transaction
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(input_block["tx"]["output"][n]["pub_key"]))
            assert vk.verify(bytes.fromhex(tx["sig"]), json.dumps(tx['input'], sort_keys=True).encode('utf-8'))
        except Exception:
            print(invalid_msg + "Bad Signature")
            return 0

        return 1
    

    def find_block(self, block_id):
        # Given block id as string, see if block exists in the blockchain and return it
        for i in range(len(self.blockchain)):
            if(self.blockchain[i]["id"] == block_id):
                return self.blockchain[i]
        return

    def create_utx(self, sk, vk, block_id, n, amt, pubkey):
        # Given info for input, amount to send and public key of recipient, create transaction

        # Check if input block actually exists
        input_block = self.find_block(block_id)
        if(input_block is None):
            print("Input block doesn't exist, exiting")
            return
        
        input_field = {
            'id': block_id,
            'n': n
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

        input_pay = input_block["tx"]["output"][n]["value"]
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
        if(self.validate_tx(utx, 0) == 0):
            print("INVALID UTX. MINING FAILED. RIP")
            return

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

        # Compute block ID
        block_id = hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf-8')).hexdigest()

        # Now create block:
        mined_block = {
            'type': self.BLOCK,
            'id': block_id,
            'nonce': nonce,
            'pow': pow,
            'prev': self.blockchain[len(self.blockchain)-1]['id'],
            'tx': utx
        }

        return mined_block
    
    def submit_json(self, json_info):
        self.connect_with_node(SERVER_ADDR, SERVER_PORT)
        self.send_to_nodes(json_info)
    
    def get_pubkeys(self):
        pubkeys = []
        for block in self.blockchain:
            if(block["tx"]["output"][0]["pub_key"] not in pubkeys):
                pubkeys.append(block["tx"]["output"][0]["pub_key"])
        return pubkeys
    
    def print_barebones_blockchain(self):
        length = 96
        for i in range(len(self.blockchain)):
            # Collect important bits of data from transaction
            block = self.blockchain[i]
            line_len = length
            block_title = "  B L O C K " + str(i+1) + " " * len(str(i))

            id = block["id"]
            input_id = block["tx"]["input"]["id"]
            output = block["tx"]["output"]
            if(len(output) == 1):
                miner = (output[0]["pub_key"], output[0]["value"])
                payee = ("N/A", 0)
                payer = ("N/A", 0)
                change = 0
            elif(len(output) == 2):
                payee = (output[0]["pub_key"], output[0]["value"])
                change = 0
                miner = (output[1]["pub_key"], output[1]["value"])
            elif(len(output) == 3):
                payee = (output[0]["pub_key"], output[0]["value"])
                change = output[1]["value"]
                miner = (output[2]["pub_key"], output[2]["value"])

            print()
            print("-" * (line_len+len(block_title)))
            print("-" * int(line_len/2) + block_title + "-" * int(line_len/2))
            print("-" * (line_len+len(block_title)))
            print("Payer: {}".format(input_id))
            print("Payee: {}".format(payee[0]))
            print("Amount paid: {}".format(payee[1]))
            print("Change: {}".format(change))
            print("Miner: {}".format(miner[0]))
            
            print("-" * (line_len+len(block_title)))

    def print_utxpool(self):
        for i in range(1, len(self.utx)+1):
            line_len = 104
            block_title = "  U T X " + str(i) + " " * len(str(i))
            print()
            print("=" * (line_len+len(block_title)))
            print("=" * int(line_len/2) + block_title + "=" * int(line_len/2))
            print("=" * (line_len+len(block_title)))
            print(json.dumps(self.utx[i-1], indent=1))
            print("=" * (line_len+len(block_title)))
            print()

    def generate_ZC(self, utx_params, ZC):
        # This "attack" takes advantage of the fact that you don't need to upload a utx to the server to mine it
        # Given an amount of ZC to generate, and the info to generate the first utx,
        #   creates and mines a series of utx's locally under various public/private keypairs
        # Since we're mining the utx's locally, there's no competition and we can guarantee we'll get the payout
        # Returns dictionary containing set of vk used as keys with values being an array of tuples containing the (blockID whose output at n=1 is change of transaction, change)

        # Create 10 random sk/vk pairs with which we will generate ZC
        keychain = []
        with open("./notAnAdv.key", 'w') as f:
            for i in range(10):
                sk = SigningKey.generate()
                vk = sk.verifying_key
                f.write(sk.to_string().hex() + " " + vk.to_string().hex() + "\n")
                keychain.append((sk,vk))

        pubkeys = self.get_pubkeys()
        keys = keychain[random.randint(0,len(keychain)-1)]

        # Create initial transaction we can start from
        utx = self.create_utx(utx_params[0], utx_params[1], utx_params[2], int(utx_params[3]), 1, pubkeys[random.randint(0,len(pubkeys)-1)])
        if(utx is None):
            print("UTX creation failed, exiting.")
            time.sleep(1)
            return
        mined = self.mine_utx(utx, keys[1])
        if(mined is None):
            print("Failed to mine initial utx. Exiting.")
            return
        
        self.submit_json(mined)
        #self.blockchain.append(mined)

        # Verify that it was added to blockchain
        time.sleep(1)
        if(self.find_block(mined["id"]) is None):
            print("Failed to upload initial utx. Exiting.")
            return

        # Now start creating some transactions
        ZC_generated = 0
        payment_blockID = mined["id"]

        # Create dictionary to hold vk's used along with transactions made using each vk
        generated = {}
        for i in range(len(keychain)):
            generated[keychain[i][1].to_string().hex()] = []

        ZC_tracker_path = "./" + keys[1].to_string().hex() + ".txt"
        with open(ZC_tracker_path, 'w') as f:
            f.write("Secret Key (Shhhhhh don't tell anyone): {}\n".format(keys[0].to_string().hex()))
            while(ZC_generated+self.COINBASE < ZC):
                payment = random.randint(1,5) # Randomly pay between 1-5 coins
                utx = self.create_utx(keys[0], keys[1], payment_blockID, 2, payment, pubkeys[random.randint(0,len(pubkeys)-1)])
                if(utx is None):
                    print("Adv utx creation failed, continuing")
                    continue
                mined = self.mine_utx(utx, keys[1])
                if(mined is None):
                    print("Adv mining failed, continuing")
                    continue
                
                # Mining successful, try to add to blockchain
                self.submit_json(mined)
                time.sleep(1)
                if(self.find_block(mined["id"]) is not None):
                    # Operation successful, save the transaction results
                    payment_blockID = mined["id"]
                    f.write("Block ID: {}\n".format(payment_blockID))
                    generated[keys[1].to_string().hex()].append((payment_blockID, self.COINBASE-payment))
                    f.write("\tZC Generated: {}\n".format(self.COINBASE-payment))
                    ZC_generated += self.COINBASE-payment
            # Add final, unspent coinbase
            generated[keys[1].to_string().hex()].append((payment_blockID, self.COINBASE))
            f.write("Block ID: {} (Coinbase)\n".format(payment_blockID))
            f.write("\tZC Generated: {}\n".format(self.COINBASE))
            f.write("Total ZC generated: {}".format(ZC_generated))
        
        return (keys[1].to_string().hex(), generated[keys[1].to_string().hex()], keys[0].to_string().hex())

    
def compute_BlockID(block):
    return hashlib.sha256(json.dumps(block['tx'], sort_keys=True).encode('utf-8')).hexdigest()

def compute_PoW(tx, nonce):
    return hashlib.sha256(json.dumps(tx, sort_keys=True).encode('utf-8') + nonce.encode('utf-8')).hexdigest()

def print_blockchain(blockchain):
    for i in range(1, len(blockchain)+1):
        line_len = 100
        block_title = "  B L O C K " + str(i) + " " * len(str(i))
        print()
        print("=" * (line_len+len(block_title)))
        print("=" * int(line_len/2) + block_title + "=" * int(line_len/2))
        print("=" * (line_len+len(block_title)))
        print(json.dumps(blockchain[i-1], indent=1))
        print("=" * (line_len+len(block_title)))
        print()


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

    time.sleep(1)

    client.start()

    time.sleep(1)

    #Connect to server 
    client.connect_with_node(SERVER_ADDR, SERVER_PORT)
    print("Starting ZachCoin™ Client:", sys.argv[1])
    time.sleep(2)
    signal.signal(signal.SIGINT, DisconnectHandler(client))

    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        slogan = " You can't spell \"It's a Ponzi scheme!\" without \"ZachCoin\" "
        print("=" * (int(len(slogan)/2) - int(len(' ZachCoin™')/2)), 'ZachCoin™', "=" * (int(len(slogan)/2) - int(len('ZachCoin™ ')/2)))
        print(slogan)
        print("=" * len(slogan),'\n')

        print(client.id)
        print(client.callback)

        x = input("\t0: Print keys\n\t1: Print blockchain\n\t2: Print UTX pool\n\t3: Create transaction\n\t4: Mine transaction\n\t5: Print all Pub Keys\n\t6: Print blockchain (barebones)\n\t7: Generate some ZachCoin\n\nEnter your choice -> ")
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
            print_blockchain(client.blockchain)
        elif x == 2:
            #print(json.dumps(client.utx, indent=1))
            client.print_utxpool()
        elif x == 3:
            pk = input("What is the public key of who you want to pay?\n\tEnter Here -> ")
            block_id = input("Which block would you like to pay from?\n\tEnter Here -> ")
            n = input("Enter the index of the payment you wish to pay from (n)\n\tEnter Here -> ")
            amt = input("How much do you want to pay?\n\tEnter Here -> ")
            utx = client.create_utx(sk, vk, block_id, int(n), int(amt), pk)
            if(utx is None):
                print("UTX creation failed, RIP")
            else:
                print("Transaction creation successful, uploading to server")
                client.submit_json(utx)
        elif x == 4:
            # Take latest UTX to mine
            if(len(client.utx) < 1):
                print("UTX pool is empty, nothing to mine")
            utx = client.utx[len(client.utx)-1]
            mined = client.mine_utx(utx, vk)
            client.utx = client.utx[:len(client.utx)-1]
            if(mined is None):
                # Mining failed, reject utx and remove
                print("Newest utx was invalid, please try again")
            else:
                success = client.validate_block(mined)
                if(success):
                    print("Mined block is valid and will be uploaded to the server")
                    client.submit_json(mined)
                    #client.blockchain.append(mined)
                else:
                    print("Mined block was invalid and will NOT be uploaded to the server")
        elif x == 5:
            pubkeys = client.get_pubkeys()
            for pubkey in pubkeys:
                print(pubkey)
        elif x == 6:
            client.print_barebones_blockchain()
        elif x == 7:
            ZC = input("How many ZachCoins would you like to generate?\n\tEnter Here -> ")
            starting_blockID = input("What is the block ID with an unused payment?\n\tEnter Here -> ")
            n = input("What is n for the unused payment?\n\tEnter Here -> ")
            utx_params = (sk, vk, starting_blockID, n)
            generated = client.generate_ZC(utx_params, int(ZC))
            print("ZachCoin generated! Public Key Associated with your ZC: {}".format(generated[0]))
            sum = 0
            ZC_tracker_path = "./" + generated[0] + ".txt"
            with open(ZC_tracker_path, 'w') as f:
                f.write("Secret Key (Shhhhhh don't tell anyone): {}\n".format(generated[2]))
                for tx in generated[1]:
                    print("Block ID: {}".format(tx[0]))
                    f.write("Block ID: {}\n".format(tx[0]))
                    print("\tZC Generated: {}".format(tx[1]))
                    f.write("\tZC Generated: {}\n".format(tx[1]))
                    sum += tx[1]
                print("Total ZC generated: {}".format(sum))
                f.write("Total ZC generated: {}".format(sum))

        time.sleep(1)
        # TODO: Add options for creating and mining transactions
        # as well as any other additional features

        input()
        
if __name__ == "__main__":
    main()