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

    def print_freq
      freq.sort_by { |c,f| c }.each { |(c,f)| puts "#{c}: #{f}" }
      nil
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
end
