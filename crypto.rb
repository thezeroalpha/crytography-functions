module Crypto
  ENGLISH_LETTER_PROB = {
    a: 0.082,
    b: 0.015,
    c: 0.028,
    d: 0.043,
    e: 0.127,
    f: 0.022,
    g: 0.020,
    h: 0.061,
    i: 0.070,
    j: 0.002,
    k: 0.008,
    l: 0.040,
    m: 0.024,
    n: 0.067,
    o: 0.075,
    p: 0.019,
    q: 0.001,
    r: 0.060,
    s: 0.063,
    t: 0.091,
    u: 0.028,
    v: 0.010,
    w: 0.023,
    x: 0.001,
    y: 0.020,
    z: 0.001
  }
  BIT5 =  [
    [0, 'A', '00000'],
    [1, 'B', '00001'],
    [2, 'C', '00010'],
    [3, 'D', '00011'],
    [4, 'E', '00100'],
    [5, 'F', '00101'],
    [6, 'G', '00110'],
    [7, 'H', '00111'],
    [8, 'I', '01000'],
    [9, 'J', '01001'],
    [10, 'K', '01010'],
    [11, 'L', '01011'],
    [12, 'M', '01100'],
    [13, 'N', '01101'],
    [14, 'O', '01110'],
    [15, 'P', '01111'],
    [16, 'Q', '10000'],
    [17, 'R', '10001'],
    [18, 'S', '10010'],
    [19, 'T', '10011'],
    [20, 'U', '10100'],
    [21, 'V', '10101'],
    [22, 'W', '10110'],
    [23, 'X', '10111'],
    [24, 'Y', '11000'],
    [25, 'Z', '11001'],
    [26, '.', '11010'],
    [27, '!', '11011'],
    [28, '?', '11100'],
    [29, '☻', '11101'],
    [30, '☺', '11110'],
    [31, '-' ,'11111']
  ]
  module String
    # Index of coincidence
    def ioc
      numerators = freq.inject ([]) { |nums, (_,f)| nums.append(f*(f-1)); nums }
      denom = self.clean.length*(self.clean.length-1)
      numerators.sum.to_f / denom.to_f
    end

    def freq
      self.clean.chars.inject({}) do |res, char|
        if res.include? char
          res[char] +=1
        else
          res[char] = 1
        end
        res
      end
    end

    def to_bin
      self.upcase.chars.inject([]) do |acc, c|
        acc << Crypto::BIT5.detect { |x| x[1] == c }.last
      end.join
    end

    def space_n n
      self.gsub(/(.{#{n}})/, '\1 ').rstrip
    end

    def print_freq
      freq.sort_by { |c,f| c }.each { |(c,f)| puts "#{c}: #{f}" }
      nil
    end

    def rotate_left n
      self.chars.rotate(n).join
    end

    def shift_d key
      alphabet = ('a'..'z').to_a
      table = alphabet.inject({}) { |ht, letter| ht[letter] = alphabet[(alphabet.index(letter)-key)%26]; ht }
      res_str = self.clean.downcase.chars.inject('') { |res, c| res += table[c]; res }
      return res_str.downcase
    end
    def shift_e key
      res_str = self.clean.chars.inject('') { |res, c| res += (key.times.inject(c) {|c| c.next[0] }) }
      res_str.upcase
    end

    def vig_e keyword
      alphabet = ('a'..'z').to_a
      keyarr = keyword.downcase.chars.map { |c| alphabet.index(c) }
      str = self.clean.gsub(' ', '').gsub /[^a-zA-Z0-9]/, ''
      raise "Only letters supported." if !str.match(/^[[:alpha:]]+$/)
      result =  str.chars.each_with_index.inject([]) do |arr, (c, str_position)|
        arr.append alphabet[(alphabet.index(c)+(keyarr[str_position % keyarr.length])) % 26]
        arr
      end
      result.map(&:upcase).join.gsub(/([A-Z]{#{keyarr.length}})/, '\1 ').strip
    end

    def vig_d keyword
      alphabet = ('a'..'z').to_a
      keyarr = keyword.downcase.chars.map { |c| alphabet.index(c) }
      str = self.clean.downcase.split.join
      raise "Only letters supported." if !str.match(/^[[:alpha:]]+$/)
      result =  str.chars.each_with_index.inject([]) do |arr, (c, str_position)|
        arr.append alphabet[(alphabet.index(c)-(keyarr[str_position % keyarr.length])) % 26]
        arr
      end
      result.map(&:downcase).join.strip
    end

    def vig_analyze keylen
      analysis = CryptAnalysis::VigAnalyze.new self.clean, keylen

      puts "nprime: #{analysis.nprime}"
      puts "Frequencies: #{analysis.print_freqs}"
      puts "Table with indices of coincidence:"
      puts analysis.print_table
      puts "Probable keywords: #{analysis.get_keywords}"
    end

    def spn_encrypt s_tab, p_tab, key, keyschedule_fn, nrounds
      spn = SPN.new s_tab, p_tab, key, keyschedule_fn, nrounds
      spn.encrypt(self.gsub(' ', '').to_i(2))
    end

    def clean
      self.downcase.gsub(/\n/, '').gsub(' ', '').gsub /[^a-zA-Z]/, ''
    end
  end

  module Integer
    def norm (mod=26)
      self % mod
    end
    def inv (mod=26)
      return nil unless self.gcd(mod) == 1

      ext_euclidian = ->(a,m) do
        return 1, 0 if m == 0
        q, r = a.divmod m
        s, t = ext_euclidian.(m, r)
        return t, s - q * t
      end

      ext_euclidian.(self, mod).first.norm
    end

     def spn_encrypt s_tab, p_tab, key, keyschedule_fn, nrounds
      spn = SPN.new s_tab, p_tab, key, keyschedule_fn, nrounds
      spn.encrypt(self)
    end
  end

  module CryptAnalysis
    class VigAnalyze
      attr_reader :nprime
      def initialize(str, keylen)
        str = str.clean.downcase
        @nprime = (str.length.to_f/keylen).ceil
        @ys = {}
        (1..keylen).each do |x|
          y = {}
          (x-1..str.length-1).step(keylen) { |i| y.include?(str[i].downcase.to_sym) ? y[str[i].downcase.to_sym] += 1 : y[str[i].downcase.to_sym] = 1 }
          @ys["y#{x}".to_sym] = y
        end
      end
      def make_table
        @ys.inject({}) { |table, (y, vs)| r = make_row(y, @nprime).first; table[r[0]] = r[1]; table}
      end
      def print_table
        table = make_table
        s = ""
        s += "y\\i (char)".center(9)
        ('a'..'z').each do |c|
          s += "|"+c.center(8)
        end
        s += "\n"
        table.each do |rowname, values|
          s += rowname.to_s.center(9)
          values.each do |val|
            s += "|"+val.to_s.center(8)+""
          end
          s += "\n"
        end
        s
      end
      def m g, y, nprime
        fsub = g
        total = 0
        ('a'..'z').each do |psub|
          freq = @ys[y.to_sym][fsub.to_sym]
          total += (ENGLISH_LETTER_PROB[psub.to_sym])*(freq.nil? ? 0 : freq)
          fsub = fsub.next[0]
        end
        (total.to_f/nprime).round(4)
      end

      def make_row y, nprime
        row = {y => []}
        ('a'..'z').each do |c|
          row[y] << m(c, y, nprime)
        end
        row
      end
      def get_keywords
        table = make_table.inject([]) do |result, (rowname, values)|
          maxvals = values.max 2
          result << maxvals.map { |x| ('a'..'z').to_a[values.index(x)] }
          result
        end
        table.first.product(*table[1..-1]).map(&:join)
      end
      def print_freqs
        @ys
      end
    end
  end

  class SPN
    def initialize s_tab, p_tab, key, keyschedule_fn, nrounds
      @s_tab = s_tab
      @p_tab = p_tab
      @keyschedule_fn = keyschedule_fn
      @key = key
      @nrounds = nrounds
    end

    # Takes i as round number, returns number
    def gen_roundkey i
      @keyschedule_fn.(i, @key)
    end

    # Takes plaintext as number, returns num
    def add_roundkey x, round_n
      x ^ (gen_roundkey round_n)
    end

    # Takes (hex) num, returns arr of (hex) nums
    def subst orig
      bits = ("%016b" % orig).split('').each_slice(4).to_a.map { |arr| arr.join }
      bits = bits.map do |str|
        @s_tab[str.to_i(2)]
      end
    end

    # Takes arr of (hex) nums, returns number
    def perm hex_val_arr
      bit_arr = hex_val_arr.map {|x| ("%04b" % x)}.join('').split('')
      res = bit_arr.each_with_index.inject([]) { |acc, (bit, i)| acc << bit_arr[@p_tab[i]] }
      res.join('')
    end

    def encrypt ptext
      puts "Plaintext: 0x#{ptext.to_s(16)}"
      10.times { print "-" }; puts
      x = ptext
      (1..@nrounds).each do |round|
        u = self.add_roundkey(x, round)
        puts "u#{round}: 0x#{u.to_s 16}"
        v = self.subst(u)
        puts "v#{round}: 0x#{v.map {|x| x.to_s 16}.join}"
        w = self.perm(v)
        puts "w#{round}: #{w.gsub(/(.{4})/, '\1 ')}"
        x = w.to_i(2)
        10.times { print "-" }; puts
      end
      y = x

      puts "Ciphertext:"
      puts "bin #{("%016b" % y).gsub(/(.{4})/, '\1 ')}"
      puts "hex #{("%04x" % y)}"
    end
  end

  class DES
    def ip(x)
      chars = x.chars
      permuted = [
        chars[57], chars[49], chars[41], chars[33], chars[25], chars[17], chars[9], chars[1],
        chars[59], chars[51], chars[43], chars[35], chars[27], chars[19], chars[11], chars[3],
        chars[61], chars[53], chars[45], chars[37], chars[29], chars[21], chars[13], chars[5],
        chars[63], chars[55], chars[47], chars[39], chars[31], chars[23], chars[15], chars[7],
        chars[56], chars[48], chars[40], chars[32], chars[24], chars[16], chars[8], chars[0],
        chars[58], chars[50], chars[42], chars[34], chars[26], chars[18], chars[10], chars[2],
        chars[60], chars[52], chars[44], chars[36], chars[28], chars[20], chars[12], chars[4],
        chars[62], chars[54], chars[46], chars[38], chars[30], chars[22], chars[14], chars[6]
      ].join

      return permuted[0..(permuted.length/2)-1], permuted[permuted.length/2..]
    end

    def pc1(k)
      chars = k.chars
      permuted = [
        chars[56], chars[48], chars[40], chars[32], chars[24], chars[16], chars[8],
        chars[0], chars[57], chars[49], chars[41], chars[33], chars[25], chars[17],
        chars[9], chars[1], chars[58], chars[50], chars[42], chars[34], chars[26],
        chars[18], chars[10], chars[2], chars[59], chars[51], chars[43], chars[35],
        chars[62], chars[54], chars[46], chars[38], chars[30], chars[22], chars[14],
        chars[6], chars[61], chars[53], chars[45], chars[37], chars[29], chars[21],
        chars[13], chars[5], chars[60], chars[52], chars[44], chars[36], chars[28],
        chars[20], chars[12], chars[4], chars[27], chars[19], chars[11], chars[3]
      ].join

      return permuted[0..(permuted.length/2)-1], permuted[(permuted.length/2)..]
    end

    def pc2(cn, dn)
      chars = (cn+dn).chars
      [
        chars[13], chars[16], chars[10], chars[23], chars[0], chars[4],
        chars[2], chars[27], chars[14], chars[5], chars[20], chars[9],
        chars[22], chars[18], chars[11], chars[3], chars[25], chars[7],
        chars[15], chars[6], chars[26], chars[19], chars[12], chars[1],
        chars[40], chars[51], chars[30], chars[36], chars[46], chars[54],
        chars[29], chars[39], chars[50], chars[44], chars[32], chars[47],
        chars[43], chars[48], chars[38], chars[55], chars[33], chars[52],
        chars[45], chars[41], chars[49], chars[35], chars[28], chars[31]
      ].join
    end

    def e a
      chars = a.chars
      [
        chars[31], chars[0], chars[1], chars[2], chars[3], chars[4],
        chars[3], chars[4], chars[5], chars[6], chars[7], chars[8],
        chars[7], chars[8], chars[9], chars[10], chars[11], chars[12],
        chars[11], chars[12], chars[13], chars[14], chars[15], chars[16],
        chars[15], chars[16], chars[17], chars[18], chars[19], chars[20],
        chars[19], chars[20], chars[21], chars[22], chars[23], chars[24],
        chars[23], chars[24], chars[25], chars[26], chars[27], chars[28],
        chars[27], chars[28], chars[29], chars[30], chars[31], chars[0]
      ].join
    end

    def c blocks
      s_boxes = [
        # S1
        [
          [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
          [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
          [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
          [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
          [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
          [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
          [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
          [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
          [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
          [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
          [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
          [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
          [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],
        # S5
        [
          [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
          [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
          [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
          [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
          [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
          [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
          [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
          [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
          [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
          [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
          [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
          [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
          [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
          [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
          [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
          [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
      ]

      blocks.each_with_index.map do |block, i|
        row_idx = (block[0]+block[5]).to_i(2)
        col_idx = (block[1..4]).to_i(2)
        ("%04b" % s_boxes[i][row_idx][col_idx])
      end.join
    end

    def p_perm c
      chars = c.chars
      [
        chars[15], chars[6],  chars[19], chars[20],
        chars[28], chars[11], chars[27], chars[16],
        chars[0],  chars[14], chars[22], chars[25],
        chars[4],  chars[17], chars[30], chars[9],
        chars[1],  chars[7],  chars[23], chars[13],
        chars[31], chars[26], chars[2],  chars[8],
        chars[18], chars[12], chars[29], chars[5],
        chars[21], chars[10], chars[3],  chars[24]
      ].join
    end
    def f a, j
      puts "Calculating f"
      puts "\trprev: #{a}"
      puts "\tkey: #{j}"
      puts "\tE(A): #{(e a)}"
      ea_plus_j = ("%048b" % ((e a).to_i(2) ^ j.to_i(2)))
      puts "\tres: #{ea_plus_j}"
      blocks = ea_plus_j.chars.each_slice(6).to_a.map(&:join)
      c = c(blocks)
      puts "\tC: #{c}"
      perm = p_perm c
      puts "\tP: #{perm}"
      perm
    end

    def gen_keys_upto n, hex_key
      bin_key = ("%064b" % hex_key)

      keys = []
      cds = []

      cds << pc1(bin_key)

      1.upto(n) do |i|
        ci, di = cds[i-1]
        if [1,2,9,16].include? i
          ci = ci.rotate_left(1)
          di = di.rotate_left(1)
        else
          ci = ci.rotate_left(2)
          di = di.rotate_left(2)
        end
        cds << [ci, di]
        keys[i] = pc2(ci, di)
      end

      keys
    end

    def g l, r, k
      li = r
      fres = f(r,k)
      ri = ("%032b" % (l.to_i(2) ^ fres.to_i(2)))

      return li, ri
    end

    def inv_ip r, l
      chars = (r+l).chars
      [
        chars[39], chars[7], chars[47], chars[15], chars[55], chars[23], chars[63], chars[31],
        chars[38], chars[6], chars[46], chars[14], chars[54], chars[22], chars[62], chars[30],
        chars[37], chars[5], chars[45], chars[13], chars[53], chars[21], chars[61], chars[29],
        chars[36], chars[4], chars[44], chars[12], chars[52], chars[20], chars[60], chars[28],
        chars[35], chars[3], chars[43], chars[11], chars[51], chars[19], chars[59], chars[27],
        chars[34], chars[2], chars[42], chars[10], chars[50], chars[18], chars[58], chars[26],
        chars[33], chars[1], chars[41], chars[9], chars[49], chars[17], chars[57], chars[25],
        chars[32], chars[0], chars[40], chars[8], chars[48], chars[16], chars[56], chars[24]
      ].join
    end

    def do_encryption nrounds
      puts "DES Encryption"
      puts "Plaintext: #{("%0x" % @hex_num)}"
      puts "Key: #{("%x" % @hex_key)}"
      puts

      bin_num = ("%064b" % @hex_num)
      keys = gen_keys_upto(nrounds, @hex_key)

      lrs = []
      lrs << ip(bin_num)

      puts "L0: #{lrs.first.first}"
      puts "R0: #{lrs.first.last}"
      80.times { print "-" }; puts

      1.upto(nrounds) do |i|
        lprev, rprev = lrs.last
        lrs << g(lprev, rprev, keys[i])

        puts "K#{i}: #{keys[i]}"
        puts "L#{i}: #{lrs.last.first}"
        puts "R#{i}: #{lrs.last.last}"
        80.times { print "-" }; puts
      end

      llast, rlast = lrs.last
      ciphertext = inv_ip(rlast, llast)

      puts "Ciphertext:"
      puts "hex #{ciphertext.to_i(2).to_s(16)}"
      puts "bin #{ciphertext.space_n(4)}"

      return ciphertext.to_i(2)
    end

    attr_reader :hex_num, :hex_key
    def initialize hex_num, hex_key
      @hex_num = hex_num
      @hex_key = hex_key
    end
  end
end
