import nltk
from collections import Counter

# Using nltk to download the list of words
nltk.download('words')
from nltk.corpus import words


valid_words = set(words.words())

#Given enccrypted text 
encr_txt_file = 'encrypted.txt'


#helper function to read files
def file_reader(f_path):
    with open(f_path, 'r') as f:
        return f.read()  

encr_txt = file_reader(encr_txt_file)



#mappings found from previous attempts, noted 
manual_map = {'f': 'e', 's': 't', 'b': 'a', 'p': 'l', 'm': 'h', 'd': 'i', 't': 's', 'v': 'n', 'j': 'o', 'q': 'f', 'l': 'd', 'r': 'b', 'c': 'r',
                  'g': 'm', 'e': 'u', 'n': 'p', 'w': 'c', 'k': 'y', 'u': 'w', 'i': 'g', 'x': 'v', 'h': 'q', 'y': 'k', 'o': 'x'}




# Most common letters in the English aplhabet (in decreasing order of frequency)
english_letter_freq = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'


#frequency analysis
def analyze_freq(text):
    text = text.replace(" ", "").replace("\n", "")  #Stripping extra characters
    return Counter(text)

# Creating a substitution map using the most frequent letters
def generate_subst_mapping(freq, freq_symbols, mappings):
    most_freq = [item[0] for item in freq.most_common(26)]  
    
   
    substitution_map = mappings.copy()

    # Fill in the remaining mappings based on frequency analysis
    cur_pos = 0
    for l in most_freq:
        if l not in substitution_map:  #Find mappings for letter that were not manually mapped
            substitution_map[l] = freq_symbols[cur_pos]
            cur_pos += 1

    return substitution_map

#function for decrypting the text after mapping is applied
def decrypt(text, substitution_map):
    decry_txt = ''.join([substitution_map.get(char, char) if char.isalpha() else char for char in text])
    return decry_txt

#Find the vaildity of the decrypted text by analyzing how many words are real words
def count_valid_words(decry_txt, valid_words):
    words = decry_txt.lower().split()
    count = sum(1 for word in words if word in valid_words)
    return count

# find the frequencies of the encrypted text (ciphertext)
encr_txt_freq = analyze_freq(encr_txt)

#find the subst map
substitution_map = generate_subst_mapping(encr_txt_freq, english_letter_freq, manual_map)

decryp_txt = decrypt(encr_txt, substitution_map)

#writing output to file
with open('plaintext.txt', 'w') as out_f:
    out_f.write(decryp_txt)

# Score the decrypted text
count = count_valid_words(decryp_txt, valid_words)

print("\nSubstitution mapping:", substitution_map)
print("\nDecrypted text:\n", decryp_txt)


