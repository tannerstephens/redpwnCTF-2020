"""
This challenge allows us to specify the bit-width of the generated random numbers.
ex. 
  L = 1, R = 2 will give us a "keyspace" of [10,11]
  L = 2, R = 3 gives [100,101,110,111]

  However
  L = 1, R = 3 would give [10,11,100,101,110,111]

It then xors the flag with the random bits and returns the cypher text

Because we know the keyspace, we can iteratively give increasing bitwidths
and from this know that the resultant cyphertest will have been xored with
random data that has its most-significant-bits as 1s

ex.
  L=1,R=2 => Random Bits: 1_1_1_1_1_1_
  L=2,R=3 =>              1__1__1__1__1__1__

By going down the line of these keyspaces, we can invert the known bits and get the flag
flag{bits_leaking_out_down_the_water_spout}
"""

from pwn import *

def main():
  context.log_level = "ERROR"

  cypher = [int(i) for i in list('0111011001001101101101001100010010010010000111110001111100011001100000001100110111110010100101000001111100010100011000011000010111010000101101010010110101001001110100010001000000000100000000011111011010110010100000000001110001101100001010011100000110000101000100100000011011010101000001000011110101010')]
  known = [0 for _ in range(len(cypher))]

  for i in range(len(cypher)):
    if (i%2) == 0:
      cypher[i] = cypher[i]^1
      known[i] = 1

  cypher[1] = 1

  known[1] = 1


  while 0 in known:
    i = known.index(0)
    l = i - 1
    r = i

    conn = remote('2020.redpwnc.tf', 31284)

    conn.send(f'{l}\r\n{r}\r\n')

    conn.recvuntil('Ciphertext: ')

    data = [int(c) for c in conn.recvline().decode().strip()]

    assert data[0] == 0

    assert len(data) == len(cypher)

    conn.close()

    for j in range(0,len(cypher),i):
      if (j%i) == 0 and not known[j]:
        cypher[j] = data[j]^1
        known[j] = 1

    plaintext_bytes = [cypher[i:i+7] for i in range(0,len(cypher),7)]  
    for pt_byte in plaintext_bytes:
      o = int(''.join([str(j) for j in pt_byte]),2)

      print(chr(o), end='')

    print()

if __name__ == '__main__':
  main()
