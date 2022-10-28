use blake2::Blake2s;

use crate::{groth16::run_groth16, marlin::run_marlin};

pub mod circuit;
pub mod groth16;
pub mod marlin;
pub mod parameters;

pub fn test_arkworks() {
    println!("-----------------------------");
    println!("Run Groth16 with bls12-381...");
    println!("-----------------------------");
    run_groth16::<ark_bls12_381::Fr, ark_bls12_381::Bls12_381>();
    println!("-----------------------------");
    println!("Run Groth16 with bn254...");
    println!("-----------------------------");
    run_groth16::<ark_bn254::Fr, ark_bn254::Bn254>();
    println!("-----------------------------");
    println!("Run Marlin with KZG10<bls12-381> and Blake2s...");
    println!("-----------------------------");
    run_marlin::<
        ark_bls12_381::Fr,
        ark_poly_commit::marlin_pc::MarlinKZG10<
            ark_bls12_381::Bls12_381,
            ark_poly::univariate::DensePolynomial<ark_bls12_381::Fr>,
        >,
        Blake2s,
    >();
    println!("-----------------------------");
    println!("Run Marlin with KZG10<bn254> and Blake2s...");
    println!("-----------------------------");
    run_marlin::<
        ark_bn254::Fr,
        ark_poly_commit::marlin_pc::MarlinKZG10<
            ark_bn254::Bn254,
            ark_poly::univariate::DensePolynomial<ark_bn254::Fr>,
        >,
        Blake2s,
    >();
}
