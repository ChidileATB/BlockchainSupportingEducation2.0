import hashlib
import json
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_data = []

        # Create the genesis block
        self.create_block(previous_hash='1')

    def create_block(self, previous_hash):
        block = Block(
            index=len(self.chain),
            previous_hash=previous_hash,
            timestamp=str(datetime.datetime.now()),
            data=self.current_data,
            hash=self.calculate_hash(len(self.chain), previous_hash, str(datetime.datetime.now()), self.current_data)
        )
        self.current_data = []
        self.chain.append(block)

    def add_data(self, student_id, encrypted_result):
        self.current_data.append({
            'student_id': student_id,
            'encrypted_result': encrypted_result
        })

    @staticmethod
    def calculate_hash(index, previous_hash, timestamp, data):
        return hashlib.sha256(f"{index}{previous_hash}{timestamp}{json.dumps(data)}".encode('utf-8')).hexdigest()

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != self.calculate_hash(
                current_block.index, current_block.previous_hash, current_block.timestamp, current_block.data
            ):
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_data(public_key, data):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

def decrypt_data(private_key, encrypted_data):
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted_data = cipher.decrypt(encrypted_data).decode()
    return decrypted_data

# Example Usage:
if __name__ == '__main__':
    blockchain = Blockchain()

    # Generate public-private key pairs for student and teacher
    student_private_key, student_public_key = generate_key_pair()
    teacher_private_key, teacher_public_key = generate_key_pair()

    # Student encrypts their result using their private key
    student_id = "Student123"
    student_result = "Pass"
    encrypted_result = encrypt_data(student_private_key, student_result)

    # Teacher verifies the result by decrypting it using student's public key
    decrypted_result = decrypt_data(student_public_key, encrypted_result)

    # Add student's encrypted result to the blockchain
    blockchain.add_data(student_id, encrypted_result)

    # Teacher validates the student's eligibility for the next class
    teacher_validation = "Eligible"
    encrypted_teacher_validation = encrypt_data(teacher_private_key, teacher_validation)

    # Add teacher's encrypted validation to the blockchain
    blockchain.add_data(student_id, encrypted_teacher_validation)

    # Create a new block with the combined data
    blockchain.create_block(previous_hash=blockchain.chain[-1].hash)

    # Check if the blockchain is valid
    print("Is blockchain valid?", blockchain.is_chain_valid())

    # View the entire blockchain
    for block in blockchain.chain:
        print(vars(block))
