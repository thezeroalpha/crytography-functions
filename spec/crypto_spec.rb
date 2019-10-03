require_relative '../crypto'
RSpec.describe Crypto do
  before(:example) do
    String.include Crypto::String
  end
  it 'can clean a string' do
    expect(" sdfkj! ".clean).to eq("sdfkj")
  end

  it 'can handle a shift cipher' do
    expect("hello".shift_e 13).to eq("URYYB")
  end

  it 'can decrypt a shift cipher' do
    expect("DHYLOVBZL".shift_d(7)).to eq("warehouse")
  end

  it 'has a correct shift cipher' do
    expect("general kenobi".shift_e(7).shift_d(7)).to eq("generalkenobi")
  end

  it 'can handle a vigenere cipher' do
    expect("hello".vig_e "starwars").to eq("ZXLCK")
  end

  it 'can decrypt a vigenere cipher' do
    expect("VTRKDVRVWK".vig_d "starwars").to eq("darthvader")
  end

  it 'has a correct vigenere cipher' do
    ek = ->(x) { x.vig_e "tolkien" }
    dk = ->(x) { x.vig_d "tolkien" }
    str = "one does not simply walk into Mordor"
    expect(dk.(ek.(str))).to eq(str.clean.downcase)
  end

  it 'can count frequency of letters' do
    txt = "one does not simply walk into Mordor"
    expect(txt.freq["o"]).to eq(6)
    expect(txt.freq["t"]).to eq(2)
  end
  it 'can analyze a vigenere cipher correctly' do
    key = "tolkien"
    txt = %q{
    'I wish it need not have happened in my time,' said Frodo.
    'So do I,' said Gandalf, 'and so do all who live to see such times.
    But that is not for them to decide.
    All we have to decide is what to do with the time that is given to us.
    }.clean
    analysis = Crypto::CryptAnalysis::VigAnalyze.new(txt.vig_e(key).clean, key.length)
    expect(analysis.nprime).to eq(25)
    expect(analysis.get_keywords).to include(key)
  end
end
