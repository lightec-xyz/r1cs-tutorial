
use ark_crypto_primitives::crh::{CRHScheme ,CRHSchemeGadget};
use ark_crypto_primitives::crh::sha256::{
    Sha256,
    constraints::{UnitVar,Sha256Gadget}
};
use ark_ff::{PrimeField, Field};
use ark_ed_on_bls12_381::Fq;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

// pub type F = ark_ed_on_bls12_381::Fq;


//这里可以使用Vec<u8>作为输入，也可以用Vec<UInt8<ConstraintF>>，应该用哪一个？
pub struct Sha256BytesGadget {
    pub input: Vec<u8>,
    pub output: Vec<u8>
}


impl <ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF> for Sha256BytesGadget{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let input_var: Vec<UInt8<_>> = UInt8::new_witness_vec(ark_relations::ns!(cs, "input"), &self.input).unwrap();
        let param_var = UnitVar::default();

        let digest_var = < Sha256Gadget<ConstraintF> as CRHSchemeGadget<Sha256, ConstraintF>>::evaluate(&param_var, &input_var).unwrap();
        
        let output_bytes = digest_var.to_bytes().into(Vec<u8>);

        Ok(())
    }
}

#[test]
fn test_crh_sha256() {

    use ark_relations::{
        ns,
        r1cs::{ConstraintSystem, Namespace}
    };
    use ark_ed_on_bls12_381::Fr;

    // let mut rng = ark_std::test_rng();
    let cs = ConstraintSystem::<Fr>::new_ref();

    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    // CRH parameters are nothing, 
    let unit = (); //sha256的空parameter
    let unit_var = UnitVar::default(); //sha256Gadget的空parameter

    let input_str = vec![0u8; 64]; 

    // Compute the hashes and assert consistency
    let computed_output = <Sha256Gadget<Fr> as CRHSchemeGadget<Sha256, Fr>>::evaluate(
        &unit_var,
        &to_byte_vars(ns!(cs, "input"), &input_str),
    )
    .unwrap();
    let expected_output = <Sha256 as CRHScheme>::evaluate(&unit, input_str).unwrap();
    dbg!(&computed_output.value().unwrap().to_vec());
    assert_eq!(
        computed_output.value().unwrap().to_vec(),
        expected_output,
        "CRH error at length"
    )

    // for &len in TEST_LENGTHS {
    //     // Make a random string of the given length
    //     let mut input_str = vec![0u8; len];
    //     rng.fill_bytes(&mut input_str);

    //     // Compute the hashes and assert consistency
    //     let computed_output = <Sha256Gadget<Fr> as CRHSchemeGadget<Sha256, Fr>>::evaluate(
    //         &unit_var,
    //         &to_byte_vars(ns!(cs, "input"), &input_str),
    //     )
    //     .unwrap();
    //     let expected_output = <Sha256 as CRHScheme>::evaluate(&unit, input_str).unwrap();
    //     assert_eq!(
    //         computed_output.value().unwrap().to_vec(),
    //         expected_output,
    //         "CRH error at length {}",
    //         len
    //     )
    // }
}
