Treasure Hunter
========================

DO NOT USE THIS LIBRARY OR COMPONENTS IF SAFETY OR SECURITY IS A CONCERN!
-----------------------------------------------------------
One more project only for fun and learning code, lets try to recovery bitcoin losted wallets with force-brute.
This is a modified version of the [secp256k1 library](https://github.com/bitcoin-core/secp256k1), altered to run as quickly as possible with **absolutely no regard for security**.  
And altered version of 
### References
Based in code in [https://github.com/llamasoft/secp256k1_fast_unsafe](https://github.com/llamasoft/secp256k1_fast_unsafe):

History
========================

The secp256k1 library is optimized C library for EC operations on curve secp256k1. The Primary bitcoin algorithms for address genereations. The secp256k1_fast_unsafe is a brilhant works that use big windows pre-calculled vales for fast address generations.

With time a lot of bitcoin wallet address have been losted. I have tried it with python but the in c is big more performatic!

Implementation details
----------------------

* Find and keep losted address in a big hashtable in memory
  * ....
  * ...
  * ...
* Randon generation a lot of address and compare multiples with big hashtable
  * 

To run
-----------

    $ ./autogen.sh
    $ ./configure
    $ make
    $ ./tests
    $ sudo make install  # optional
