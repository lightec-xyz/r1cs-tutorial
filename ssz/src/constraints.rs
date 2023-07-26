
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


//使用Vec<u8>作为输入，
pub struct Sha256BytesGadget1 {
    pub input: Vec<u8>,
    pub output: Vec<u8>  //output 应该是可以mut的，以便带出计算结果
}


//使用Vec<UInt8<ConstraintF>>
pub struct Sha256BytesGadget2 <ConstraintF:PrimeField> {
    pub input: Vec<UInt8<ConstraintF>>,
    pub output: Vec<UInt8<ConstraintF>>
}


impl <ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF> for Sha256BytesGadget1{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        //此处将Vec<u8> 转换为 Vec<UInt8<ConstraintF>>, 显式的加了约束。
        let input_var: Vec<UInt8<_>> = UInt8::new_witness_vec(ark_relations::ns!(cs, "input"), &self.input).unwrap();
        let param_var = UnitVar::default();

        let digest_var = < Sha256Gadget<ConstraintF> as CRHSchemeGadget<Sha256, ConstraintF>>::evaluate(&param_var, &input_var).unwrap();
     
        //将digest_var 转换为Vec<u8>
        let mut digest_bytes: Vec<u8> = vec![];
        for e in digest_var.to_bytes().unwrap() {
            digest_bytes.push(e.value().unwrap());
        }

        //如何赋值给self.output，赋值过程需要加约束吗？
        self.output = digest_bytes;
    
        Ok(())
    }
}

impl <ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF> for Sha256BytesGadget2<ConstraintF>{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        //self.input 输入给evalute时没有显式的加约束关系，是隐式的加了吗？
        let param_var = UnitVar::default();
        let digest_var = < Sha256Gadget<ConstraintF> as CRHSchemeGadget<Sha256, ConstraintF>>::evaluate(&param_var, &self.input).unwrap();
        

        //如何赋值给self.output，赋值过程需要加约束吗？
        self.output = digest_var.to_bytes().unwrap();
    
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
