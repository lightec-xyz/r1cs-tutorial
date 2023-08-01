use core::{borrow::Borrow, iter, marker::PhantomData};
use ark_crypto_primitives::crh::{CRHScheme ,CRHSchemeGadget};
use ark_crypto_primitives::crh::sha256::{
    Sha256,
    constraints::{UnitVar,DigestVar, Sha256Gadget}
};
use ark_ff::{PrimeField, Field};
use ark_ed_on_bls12_381::Fq;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use hex::ToHex;
use crate::sha256::Sha256Bytes;

const SHA256_BYTES_INPUT_LEN: usize = 64;
const SHA256_BYTES_DIGEST_LEN: usize = 32;


pub struct Sha256BytesGadget <ConstraintF:PrimeField> {
    pub input: Vec<UInt8<ConstraintF>>,
}


impl<ConstraintF: PrimeField> Default for Sha256BytesGadget<ConstraintF> {
    fn default() -> Self {
        Self {
            input: iter::repeat(0u8).take(64).map(UInt8::constant).collect(),
        }
    }
}


impl<ConstraintF: PrimeField> Sha256BytesGadget<ConstraintF> {
    pub fn digest(data: &[UInt8<ConstraintF>]) -> Result<DigestVar<ConstraintF>, SynthesisError> { //self不是
        assert_eq!(data.len(), SHA256_BYTES_INPUT_LEN);
        
        let param_var = UnitVar::default();
        let digest_var = < Sha256Gadget<ConstraintF> as CRHSchemeGadget<Sha256, ConstraintF>>::evaluate(&param_var, &data).unwrap();
        assert_eq!(digest_var.value()?.len(), SHA256_BYTES_DIGEST_LEN);
        Ok(digest_var)
    }

}

impl<ConstraintF> CRHSchemeGadget<Sha256Bytes, ConstraintF> for Sha256BytesGadget<ConstraintF>
where
    ConstraintF: PrimeField,
{
    type InputVar = [UInt8<ConstraintF>];
    type OutputVar = DigestVar<ConstraintF>;
    type ParametersVar = UnitVar<ConstraintF>;

    // #[tracing::instrument(target = "r1cs", skip(_parameters))]
    fn evaluate(
        _parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::digest(input)
    }
}




struct Sha256BytesCircuit {
    input: Vec<u8>,
    output: Vec<u8>,
}

impl <ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF> for Sha256BytesCircuit{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {

        let input: &[u8] = &self.input;
        let input_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "input"), input)?;
       
        let output: &[u8] = &self.output;
        let output_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "output"), output)?;

        let param_var = UnitVar::default();
        let digest_var = Sha256BytesGadget::evaluate(&param_var, &input_var)?.0;  //获取hash

        //check digest = hash
        output_var.enforce_equal(&digest_var)?; //check 
        
        Ok(()) //将() 输出
    }   
}



#[test] 
// 测试sha256BytesGadget
fn test_sha256bytes_gadget(){
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use ark_ed_on_bls12_381::Fr;
    use hex;

    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    let cs = ConstraintSystem::<Fr>::new_ref(); //create a new constraint system
    let input_vec = vec![0u8;64];
    let input_var = to_byte_vars(cs, &input_vec);

    let digest_vec =  Sha256BytesGadget::digest(&input_var).unwrap().0;
    let digest_val = digest_vec.value().unwrap();
    let digest_hex = hex::encode(&digest_val);
    println!("digest_hex {:?}", digest_hex);
}



#[test]
// 测试sha256BytesCircuit
fn test_crh_sha256bytes_circuit() {
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ed_on_bls12_381::Fr;
    use hex;

    // let mut rng = ark_std::test_rng();
    let cs = ConstraintSystem::<Fr>::new_ref(); //create a new constraint system

    let input_vec = vec![0u8; 64];
    let output_vec = Sha256Bytes::digest(&input_vec);
    println!("input_vec {:?}", hex::encode(&input_vec));  //borrow value 
    println!("output_vec {:?}", hex::encode(&output_vec));

    let circuit = Sha256BytesCircuit{
        input: input_vec,
        output: output_vec
    };

    circuit.generate_constraints(cs.clone()).unwrap();
    let is_satisfied = cs.is_satisfied().unwrap();
    assert!(is_satisfied);

}