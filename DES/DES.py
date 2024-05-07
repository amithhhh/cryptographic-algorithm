from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

def Encryption(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), DES.block_size))
    return ciphertext

def Decryption(key, data):
    decipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = unpad(decipher.decrypt(data), DES.block_size)
    return decrypted_data.decode('utf-8')

if __name__ == "__main__":
    file_path = input("[+] Enter The File You Want To Encrypt: ")
    with open(file_path,'r') as main_f:
    	data = main_f.read()
    choice = input("[+] Enter Your Choice (Encryption/Decryption): ")
    main_f.close()

    if choice == 'Encryption':
        key = get_random_bytes(8)
        with open('key.txt','w') as f:
             f.write(binascii.hexlify(key).decode()) #print("[*] Key:", binascii.hexlify(key).decode())
        cipher = Encryption(key, data)
        print(f'[*] Cipher Text: {binascii.hexlify(cipher).decode()}')
        with open(file_path,'w') as main_f:
        		main_f.write(binascii.hexlify(cipher).decode())
        f.close()
        main_f.close()
    elif choice == 'Decryption':
        f = open('key.txt','r')
        key_hex = f.read()
        key = binascii.unhexlify(key_hex)
        plaintext = Decryption(key,binascii.unhexlify(data))
        print(f'[*] Plain Text: {plaintext}')
        with open(file_path,'w') as main_f:
        		main_f.write(plaintext)
        f.close()
        main_f.close()
	
