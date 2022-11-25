# ZK-Sudoku

This repo use multiple SNARK library to implment circuit of [Sudoku](https://vivianblog.hashnode.dev/how-to-create-a-zero-knowledge-dapp-from-zero-to-production#heading-1-create-the-circuit) 

+ Arkworks
+ Circom
+ dusk-Plonk
+ ZK-Garage-Plonk
+ Jellyfish
+ Plonky2
+ Halo2

In order to reduce the size of Public Inputs, Sha256 is used to compress unsolved-inputs in the implementation of Arkworks and Circom, and other implementations need to be further completed.
