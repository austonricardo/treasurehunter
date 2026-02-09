# Recuperação de Chaves Privadas de Carteiras Digitais Perdidas

## Introdução

No universo das criptomoedas, como o Bitcoin, a posse é determinada pela exclusividade do conhecimento da chave privada. Não há uma entidade centralizada que reconheça a propriedade. Essa característica traz vantagens como anonimato e segurança, porém, também apresenta o risco de perda irreversível dos ativos. Estima-se que em 2017 havia cerca de US$ 27,2 bilhões em ativos perdidos apenas na blockchain do Bitcoin. Outra pesquisa, em 2023, revelou que até 2022, 4 milhões de Bitcoins, equivalente a USD 140 bilhões, haviam sido perdidos de forma irreversível.

Analogamente, esse desafio pode ser comparado ao dos caçadores de tesouros que buscam fortunas em navios naufragados, como o famoso galeão San José, que transportava uma fortuna estimada em US$ 60 bilhões.

## Desafios

O custo computacional do processamento paralelo distribuído é alto. Desenvolver um coordenador de computação distribuída e paralela para a grid mobile é um desafio significativo.

## Proposta de Solução / Modelos de Negócio / Operação

### M01 - Criação de um Grid de Mobapp

Neste modelo, pretende-se utilizar o processamento ocioso de smartphones para criar um grid mobile. O objetivo é distribuir o processamento necessário para a descoberta de chaves privadas de carteiras abandonadas ou perdidas. Os colaboradores mobile seriam recompensados monetariamente de acordo com os processamentos realizados. Como o custo computacional do teste de chaves é bem menor do que o atual Proof of Work (Prova de Trabalho) da mineração, o esforço de processamento se justifica. Este modelo também se enquadra no conceito de economia colaborativa, similar ao Uber, pois o maior custo operacional, que é criar um grid com poder computacional capaz de quebrar as chaves em tempo aceitável, é repassado para os colaboradores da rede, praticamente sem onerá-los, uma vez que utiliza poder computacional ocioso que pode ser remunerado por isso.

### Desenvolvendo Ideias

O principal algoritmo criptográfico utilizado no Bitcoin e em outras criptomoedas é o de curva elíptica, conhecido como ECDSA (Elliptic Curve Digital Signature Algorithm). No ECDSA, as chaves privadas correspondem a um número inteiro representado por 256 bits. Em termos simples, isso implica em uma quantidade enorme de combinações possíveis. Tornando a tarefa de descobrir uma chave para determinada carteira praticamente impossível.

## Observações e Explicações

Este projeto não compromete a segurança das criptomoedas, pois as carteiras ativas geralmente são transformadas em novas carteiras a cada transação, tornando inviável a aplicação desse método para carteiras ativas. Além disso, romper a segurança das criptomoedas acabaria com seu valor e, consequentemente, o propósito do projeto.

## Fatos e Referências

- [Quase R$ 120 bilhões em bitcoins estão perdidos para sempre](https://olhardigital.com.br/noticia/quase-r-120-bilhoes-em-bitcoins-estao-perdidos-para-sempre-estima-empre/72614)
- [How Many Bitcoins Have Been Lost?](https://originstamp.com/blog/how-many-bitcoins-have-been-lost/)
- [How much would it cost in U.S. dollars to brute force a 256 bit key in a year?](https://crypto.stackexchange.com/questions/1145/how-much-would-it-cost-in-u-s-dollars-to-brute-force-a-256-bit-key-in-a-year)
- [Bitcoin: A Peer-to-Peer Electronic Cash System](https://bitcoin.org/bitcoin.pdf)
- [How to import private keys](https://en.bitcoin.it/wiki/How_to_import_private_keys)
- [How to import private keys in Bitcoin Core 0.7+](https://en.bitcoin.it/wiki/Help:How_to_import_private_keys_in_Bitcoin_Core_0.7%2B)
- [How Bitcoin Works Under the Hood](https://www.youtube.com/watch?v=-UcCMjQab4w)
- [Galeão com tesouro de até 60 bilhões é encontrado na Colômbia](https://oglobo.globo.com/sociedade/historia/galeao-com-tesouro-de-ate-60-bilhoes-encontrado-na-colombia-18235251)
- [How to recover ECDSA private key?](https://eprint.iacr.org/2014/636.pdf)
- [Transactions](https://pdfs.semanticscholar.org/d2ef/c8d77de5b6fdb9c8dd4150bcd984dca5a607.pdf)
- [How Sony's PlayStation 3 could have been hacked](https://www.youtube.com/watch?v=-UcCMjQab4w)

-----------------------------------------------------------

# Recovering Lost Digital Wallet Private Keys

## Introduction

In the world of cryptocurrencies like Bitcoin, ownership is determined by the unique knowledge of the private key. There is no centralized entity that recognizes ownership. This characteristic brings benefits such as anonymity and security, but also presents the risk of irreversible loss of assets. It is estimated that in 2017, there were approximately $27.2 billion in lost assets just in the Bitcoin blockchain. Another research in 2023 revealed that until 2022, 4 million Bitcoins, equivalent to USD 140 billion, had been irreversibly lost.

Analogously, this challenge can be compared to that of treasure hunters seeking fortunes in sunken ships, like the famous galleon San José, which transported an estimated fortune of $60 billion.

## Challenges

The computational cost of distributed parallel processing is high. Developing a coordinator for distributed and parallel computing for the mobile grid is a significant challenge.

## Proposed Solution / Business Models / Operation

### M01 - Creating a Mobapp Grid

In this model, the aim is to utilize the idle processing power of smartphones to create a mobile grid. The goal is to distribute the processing required for discovering private keys of abandoned or lost wallets. Mobile collaborators would be monetarily rewarded according to the processing performed. Since the computational cost of key testing is much lower than the current Proof of Work (PoW) of mining, the processing effort is justified. This model also fits into the concept of collaborative economy, similar to Uber, as the major operational cost, which is creating a grid with computational power capable of breaking keys in an acceptable time, is passed on to network collaborators, practically without burdening them, as it uses idle computational power that can be remunerated for it.

### Developing Ideas

The primary cryptographic algorithm used in Bitcoin and other cryptocurrencies is the elliptic curve, known as ECDSA (Elliptic Curve Digital Signature Algorithm). In ECDSA, private keys correspond to an integer represented by 256 bits. Statistically, this implies a huge number of possible combinations.

## Observations and Explanations

This project does not compromise the security of cryptocurrencies, as active wallets are usually transformed into new wallets with each transaction, making it impractical to apply this method to active wallets. Moreover, compromising the security of cryptocurrencies would destroy their value and, consequently, the purpose of the project.

## Facts and References

- [Nearly R$ 120 billion in bitcoins are lost forever](https://olhardigital.com.br/noticia/quase-r-120-bilhoes-em-bitcoins-estao-perdidos-para-sempre-estima-empre/72614)
- [How Many Bitcoins Have Been Lost?](https://originstamp.com/blog/how-many-bitcoins-have-been-lost/)
- [How much would it cost in U.S. dollars to brute force a 256 bit key in a year?](https://crypto.stackexchange.com/questions/1145/how-much-would-it-cost-in-u-s-dollars-to-brute-force-a-256-bit-key-in-a-year)
- [Bitcoin: A Peer-to-Peer Electronic Cash System](https://bitcoin.org/bitcoin.pdf)
- [How to import private keys](https://en.bitcoin.it/wiki/How_to_import_private_keys)
- [How to import private keys in Bitcoin Core 0.7+](https://en.bitcoin.it/wiki/Help:How_to_import_private_keys_in_Bitcoin_Core_0.7%2B)
- [How Bitcoin Works Under the Hood](https://www.youtube.com/watch?v=-UcCMjQab4w)
- [Galleon with treasure of up to $60 billion found in Colombia](https://oglobo.globo.com/sociedade/historia/galeao-com-tesouro-de-ate-60-bilhoes-encontrado-na-colombia-18235251)
- [How to recover ECDSA private key?](https://eprint.iacr.org/2014/636.pdf)
- [Transactions](https://pdfs.semanticscholar.org/d2ef/c8d77de5b6fdb9c8dd4150bcd984dca5a607.pdf)
- [How Sony's PlayStation 3 could have been hacked](https://www.youtube.com/watch?v=-UcCMjQab4w)

One more project only for fun, POC and learning code, lets try to recovery bitcoin losted wallets with force-brute.
This is a modified version of the [secp256k1 library](https://github.com/bitcoin-core/secp256k1), altered to run as quickly as possible with **absolutely no regard for security**.  
And altered version of 
### References
Based in code in [https://github.com/llamasoft/secp256k1_fast_unsafe](https://github.com/llamasoft/secp256k1_fast_unsafe):

History
========================

The secp256k1 library is optimized C library for EC operations on curve secp256k1. The Primary bitcoin algorithms for address genereations. The secp256k1_fast_unsafe is a brilhant works that use big windows pre-calculled vales for fast address generations.

This is only the POC not entire project.

Implementation details
----------------------

* Find and keep losted address in a big hashtable
  * ....
* Randon generation a lot of address and compare multiples with big hashtable
  * 

To run
-----------

    $ ./run.sh

To compile
-----------

    $ 

PS: forgive a little trashs of code :) .
