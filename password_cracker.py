import hashlib
import os
import time

# Current directory and file paths
current_dir = os.path.dirname(os.path.realpath(__file__))  # Get current directory
print('filepath', current_dir)
shadow_file= os.path.join(current_dir, 'shadow')  # Path to shadow file



#list of hashing algorithms to be applied
algos = ['md5', 'sha1', 'sha256', 'sha3_384', 'sha512','sha224', 'sha3_224','sha3_256','sha3_512', 'sha384'  ]

#dictionary to store all info of cracked user passwords
cracked_pwds = {}  



dict_file = 'dictionary.txt'
pwd_file = 'passwords.txt'

uhashes = {}



#Get paswords from the dictionary file
def read_dict(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]
    


#get hashed passwords from the shadow file
def read_shadow():
    with open(shadow_file, 'r') as file:
        for line in file:
            user, passwd_hash = line.split(':', 1)
            uhashes[user] = passwd_hash.strip()
       

subst_mapping = {
    'a': 'b', 'b': 'r', 'c': 'w', 'd': 'l', 'e': 'f', 'f': 'q', 'g': 'i', 'h': 'm',
    'i': 'd', 'j': 'a', 'k': 'y', 'l': 'p', 'm': 'g', 'n': 'v', 'o': 'j', 'p': 'n',
    'q': 'h', 'r': 'c', 's': 't', 't': 's', 'u': 'e', 'v': 'x', 'w': 'u', 'x': 'o',
    'y': 'k', 'z': 'z'
}

# get the substitution cipher mapping
def get_subst(password):
    return ''.join(subst_mapping.get(char, char) for char in password)


# Decrypts leetspeak passwords
def leet_combos(passwords):
    leet_dict = {'a': '4', 'b': '8', 'e': '3', 'i': '!', 'l': '1', 'o': '0', 't': '7', 's': '5', 'z': '2', 'g': '6'}
    leet_passwords = []
    
    for password in passwords:
        translated_pwd = ''.join(leet_dict.get(char, char) for char in password)
        leet_passwords.append((password, translated_pwd))
    
    return leet_passwords


# Find possibile pwds by appyling substitution cipher
def subst_cipher_combos(pwds_list):
    subst_combos = []

    for p in pwds_list:
        encypt_pwd = get_subst(p)
        subst_combos.append((p, encypt_pwd))  
    return subst_combos


# Caesar cipher for shifting chars 1 thorugh 25 places of the alphabet
def caesar_cipher_combos(pwds_list):
    caesar_combos = []

    for shift in range(1, 26):  
        for p in pwds_list:
            shifted_pwd = ''.join(
                chr((ord(char) - (65 if char.isupper() else 97) + shift) % 26 + (65 if char.isupper() else 97)) 
                if char.isalpha() else char for char in p
            )
            caesar_combos.append((p, shifted_pwd))  # Store the original and transformed passwods
    return caesar_combos

# Crack salted password for user 2
def salted_pwd():
    if 'user2' in uhashes:
        dictionary = read_dict(dict_file)
        u2hash = uhashes['user2']
        salt_range = range(0, 100000)  # Salt in the range 00000 to 99999

        for p in dictionary:
            for s in salt_range:
                salt_str = f'{s:05d}'  # conversion to string
                salted_pwd = p + salt_str

                hashed_pwd = hashlib.md5(salted_pwd.encode()).hexdigest()

                # Check if the hash matches
                if hashed_pwd == u2hash:
                    finish_time = time.time()
                    cracked_pwds['user2'] = {
                        'password': p,
                        'algorithm': 'md5',
                        'salt': salt_str,
                        'time': finish_time - start_time

                    }
                    print(f"Cracked user2: {p} with salt {salt_str} cracking time {cracked_pwds['user2'   ]['time']:.2f} seconds")
                    return

        print("Failed to crack user2 ")




# Find matches between passwords and different hashed pwds
def find_matches(pwd_combos):
    del_users = []

    for og_pwd, hashed_pwd in pwd_combos:
        for algo in algos:
            hash_instance = hashlib.new(algo)
            hash_instance.update(hashed_pwd.encode())  # Encode and hash the transformed password
            computed_hash = hash_instance.hexdigest()  # Get hex digest of hashed value
            
            for user, stored_hash in uhashes.items():
                if computed_hash == stored_hash:
                    finish_time = time.time()  # End time for comparison
                    cracked_pwds[user] ={'password': og_pwd, 'algorithm': algo,'time': finish_time-start_time}   # Store original password info
                    print(f"Cracked  {user}: {og_pwd} cracking time {cracked_pwds[user]['time']:.2f} seconds")
                    del_users.append(user)

    for user in del_users:
        uhashes.pop(user)

# write all  cracked passwords to the passwords.txt file
def write_output(file_path, data):
    with open(file_path, 'w') as file:
        sorted_users = sorted(data.keys(), key=lambda u: int(u[4:]))  # Assumes 'user' prefix
        for user in sorted_users:
            info = data[user]
            file.write(f'{user}:{info["password"]}\n')



#main
def pwd_crack():
    #reading the dict
    pwd_dict = read_dict(dict_file)
    
    # generating values of possible passwords, using ceaser cipher, leetspeak and substitution methods
    pwd_caesar = caesar_cipher_combos(pwd_dict)
    pwds_leet = leet_combos(pwd_dict)
    pwds_subst = subst_cipher_combos(pwd_dict)

    og_pwds = [(password, password) for password in pwd_dict]  # Original passwords map to themselves
    pwd_combos = og_pwds + pwd_caesar + pwds_leet + pwds_subst


    global start_time
    start_time = time.time()  # Start time for comparison
    # Match each variant against the stored hashes
    find_matches(pwd_combos)

    # Crack user2's password with salt after all others
    salted_pwd()




if __name__ == '__main__':
    # Parsing the shadow file
    read_shadow()
    
    # Crack the passwords
    pwd_crack()

    # Writing cracked pwds to the output file
    write_output(pwd_file, cracked_pwds)
