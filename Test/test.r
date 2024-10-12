require 'rspec'
require 'ffi'

module AES
  extend FFI::Library
  ffi_lib './aes-gui-1st-copy.so'

  attach_function :aes_encrypt, [:pointer, :pointer, :pointer], :void
  attach_function :aes_decrypt, [:pointer, :pointer, :pointer], :void
  attach_function :key_expansion, [:pointer, :pointer], :void
end

RSpec.describe AES do
  let(:key) { [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F].pack('C*') }
  let(:plaintext) { "Hello, World!".ljust(16, "\0") }
  
  describe '.aes_encrypt' do
    it 'encrypts the plaintext' do
      ciphertext = FFI::MemoryPointer.new(:char, 16)
      AES.aes_encrypt(plaintext, key, ciphertext)
      expect(ciphertext.read_string(16)).not_to eq(plaintext)
    end
  end

  describe '.aes_decrypt' do
    it 'decrypts the ciphertext back to plaintext' do
      ciphertext = FFI::MemoryPointer.new(:char, 16)
      AES.aes_encrypt(plaintext, key, ciphertext)
      
      decrypted = FFI::MemoryPointer.new(:char, 16)
      AES.aes_decrypt(ciphertext, key, decrypted)
      expect(decrypted.read_string(16)).to eq(plaintext)
    end
  end

  describe '.key_expansion' do
    it 'expands the key' do
      expanded_key = FFI::MemoryPointer.new(:char, 176)
      AES.key_expansion(key, expanded_key)
      expect(expanded_key.read_string(176)).not_to eq(key * 11)
    end
  end
end
