Test for weak AES keys when used in Galois Counter Mode with a block size
of 128 bits, as explained in the paper "Cycling Attacks on GCM, GHASH and 
Other Polynomial MACs and Hashes": https://eprint.iacr.org/2011/202.pdf

Also, the code can generate safe keys which are above a specific strength
threshold.

