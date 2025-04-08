import sys
import pefile
import peutils

pe_file = sys.argv[1]
pe = pefile.PE(pe_file)
imphash = pe.get_imphash()
print ("ImpHash is\n",imphash)

print ("\nSection HASHes:\nMD5")
for section in pe.sections:
  print (section.Name, "MD5 hash:", section.get_hash_md5())

print ("SHA256")
for section in pe.sections:
  print (section.Name, "SHA256 hash:", section.get_hash_sha256())
