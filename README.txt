
  Usage:  encryptor <filename>
          Reads <filename>, encrypts it, writes <filename>.enc
 
  Key derivation:
    key[32] = SHA-256( argv[1] )   (hash of the filename string, not file contents)
 
  .enc file layout:
    [0 ..15]        key[0..15]        (first half of SHA-256 digest)
    [16..16+N-1]    ciphertext        (N = plaintext length)
    [16+N..31+N]    key[16..31]       (second half of SHA-256 digest)
 
  Per-byte cipher (reverse-engineered from FUN_004098b0):
    DECRYPT:  ct -> bit_permute -> cond_rotate -> nibble_step -> gf_mix -> pt
    ENCRYPT:  pt -> gf_mix      -> ns_inv      -> cr_inv      -> bp_inv -> ct
 
   Key used per byte position:
     even positions: key[0]
     odd  positions: key[31]
 