require_relative "crypto.rb"

# Add cryptography capabilities to strings from my module
String.include Crypto::String

# Start working:
#
# Encrypt 'hello' with a shift cipher with key 4
str = "hello"
key = 4
puts "encrypt 'hello' with a shift of 4: "+str.shift_e(key)

# Decrypt a string that was encrypted with a shift cipher with key 7
str="olssv"
key = 7
puts "decrypt 'olssv' with an encryption shift of 7: "+str.shift_d(key)

# Cryptanalysis of the Vigenere cipher using a known probable keyword length
puts "Analyze the Vigenere encrypted text 'NNWVVNKBHSIECWVFMSKOUGSQSIZBPMYZAHGFZRIFTUCDZQNSKOAVHRRJTWGSNJKKOYKCGCBZHKHMVHLAJKVDHNJULJJEHRIX'"
str = "NNWVVNKBHSIECWVFMSKOUGSQSIZBPMYZAHGFZRIFTUCDZQNSKOAVHRRJTWGSNJKKOYKCGCBZHKHMVHLAJKVDHNJULJJEHRIX"
keyword_length = 5
str.vig_analyze(keyword_length)

# Decrypting a Vigenere cipher with a keyword
puts "Decrypt it with the Vigenere cipher:"
keyword = "frodo"
puts str.vig_d(keyword)

# You can also encrypt with Vigenere by doing "something".vig_e(keyword)
