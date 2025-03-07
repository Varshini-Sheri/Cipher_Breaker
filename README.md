# Cipher_Breaker

## Overview  
This homework assignment focuses on breaking authentication systems using dictionary attacks and cracking substitution ciphers. The goal is to understand the security vulnerabilities in password hashing and encryption methods.  

The assignment consists of two main tasks:  
1. **Password Cracking with Dictionary Attacks**  
2. **Breaking Substitution Ciphers**  

---

## Task 1: Password Cracking with Dictionary Attacks  
In this task, the goal is to crack user passwords stored in a **simplified `/etc/shadow` file** by performing an offline dictionary attack. Different challenges include:  
- Cracking **MD5, SHA1, and SHA256** hashed passwords.  
- Handling **salted passwords**.  
- Deciphering passwords encoded with a **Caesar cipher** before hashing.  
- Cracking passwords written in **leet speak**.  

### Steps to Complete Task 1  
1. Use the provided `dictionary.txt` as a base for cracking passwords.  
2. Implement a function to hash each word in the dictionary and compare it to the stored hashes.  
3. Apply transformations where necessary:  
   - Shift text for **Caesar cipher-encoded passwords**.  
   - Convert **leet speak passwords** back to standard English.  
   - Append numeric **salt values** to dictionary words before hashing.  
4. Output cracked passwords in `passwords.txt` in the required format.  

### Files for Task 1  
- `password_cracker.py` – Implements the dictionary attack.  
- `dictionary.txt` – A list of possible passwords.  
- `shadow.txt` – A simplified version of a Linux shadow file containing password hashes.  
- `passwords.txt` – Stores cracked passwords in the correct format.  
- `explanation_1.txt` – Explanation of the approach and execution time analysis.  

---

## Task 2: Breaking Substitution Ciphers  
For this task, user7 has encrypted their password using a **custom substitution cipher**. Your goal is to analyze an **encrypted text file** and determine the letter mapping used in the cipher. Then, use this mapping to **decrypt user7’s password**.  

### Steps to Complete Task 2  
1. Analyze `encrypted.txt` to determine the substitution pattern.  
2. Use **frequency analysis** to map common letter substitutions.  
3. Apply the mapping to the encrypted text and recover the plaintext.  
4. Use the same mapping to transform words in `dictionary.txt` and find user7’s password.  
5. Output the decrypted text in `plaintext.txt`.  

### Files for Task 2  
- `analysis.py` – Performs frequency analysis to determine the letter mapping.  
- `encrypted.txt` – A sample of encrypted text using the same cipher as user7’s password.  
- `plaintext.txt` – Stores the decrypted text.  
- `explanation_2.txt` – Explanation of the decryption approach.  

---
