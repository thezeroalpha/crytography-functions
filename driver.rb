require_relative "crypto.rb"

# Add cryptography capabilities to strings & ints from my module
String.include Crypto::String
Integer.include Crypto::Integer

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

# Substitution-permutation network
puts "\nUse an SPN for encryption:"
# Define the variables:
s_table = {
  0x0 => 0xE,
  0x1 => 0xA,
  0x2 => 0x0,
  0x3 => 0x5,
  0x4 => 0x2,
  0x5 => 0xC,
  0x6 => 0xF,
  0x7 => 0x3,
  0x8 => 0x7,
  0x9 => 0x9,
  0xA => 0x8,
  0xB => 0xD,
  0xC => 0x1,
  0xD => 0xB,
  0xE => 0x6,
  0xF => 0x4
}
p_table = {
  0 => 12,
  1 => 9,
  2 => 0,
  3 => 1,
  4 => 15,
  5 => 8,
  6 => 11,
  7 => 13,
  8 => 7,
  9 => 2,
  10 => 3,
  11 => 14,
  12 => 4,
  13 => 5,
  14 => 6,
  15 => 10
}
keyschedule_fn = ->(i, key) do
  keystr = ("%016b" % key)
  keystr[4*i-3-1..4*i+12-1].to_i(2)
end
key = 0xA1D5B08F
num_rounds = 5

"0010 0110 1011 0111".spn_encrypt s_table, p_table, key, keyschedule_fn, num_rounds

# Encryption using DES
plaintext = 0x0123456789ABCDEF
key = 0x133457799BBCDFF1
num_rounds = 16 # for full DES
des = Crypto::DES.new plaintext, key
des.do_encryption num_rounds
