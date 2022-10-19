use blake2::Blake2s;
use groth16::run_groth16;
use marlin::run_marlin;

pub mod circuit;
pub mod groth16;
pub mod marlin;

fn main() {
    println!("Run Groth16 with bls12-381...");
    run_groth16::<ark_bls12_381::Fr, ark_bls12_381::Bls12_381>();
    println!("Run Groth16 with bn254...");
    run_groth16::<ark_bn254::Fr, ark_bn254::Bn254>();
    println!("Run Marlin with bls12-381...");
    run_marlin::<
        ark_bls12_381::Fr,
        ark_poly_commit::marlin_pc::MarlinKZG10<
            ark_bls12_381::Bls12_381,
            ark_poly::univariate::DensePolynomial<ark_bls12_381::Fr>,
        >,
        Blake2s,
    >();
    println!("Run Marlin with bn254...");
    run_marlin::<
        ark_bn254::Fr,
        ark_poly_commit::marlin_pc::MarlinKZG10<
            ark_bn254::Bn254,
            ark_poly::univariate::DensePolynomial<ark_bn254::Fr>,
        >,
        Blake2s,
    >();
}
