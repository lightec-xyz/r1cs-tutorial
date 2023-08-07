use ark_crypto_primitives::crh::{CRHScheme,sha256};
use ark_std::rand::Rng;
use core::borrow::Borrow;
pub type Error = Box<dyn ark_std::error::Error>;


#[derive(Clone)]
pub struct Sha256Bytes;

impl Sha256Bytes{
    pub fn digest(input: &Vec<u8>) ->Vec<u8>{
        let empty_param = ();
        let digest = <sha256::Sha256 as CRHScheme>::evaluate(&empty_param, input.clone()).unwrap();
        digest
    }      
}


impl CRHScheme for Sha256Bytes {
    type Input = Vec<u8>;
    // This is always 32 bytes. It has to be a Vec to impl CanonicalSerialize
    type Output = Vec<u8>;
    // There are no parameters for SHA256
    type Parameters = ();

    // There are no parameters for SHA256
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    // Evaluates SHA256(input)
    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        Ok(Sha256Bytes::digest(input.borrow()).to_vec())
    }

}


#[test]
fn test_sha256_as_crh(){
    let expected = String::from("80a0d24abf3c8c3f47f3e6bcd6fc6e3b36bd1de50b6e721b2b0cb91a9376211f");
    let input = hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
    let mut rng = ark_std::test_rng();

    let hash_param = <sha256::Sha256 as CRHScheme>::setup(&mut rng).unwrap();
    let digest = <sha256::Sha256 as CRHScheme>::evaluate(&hash_param, input).unwrap();
    let digest_str = hex::encode(digest);
    assert_eq!(expected, digest_str);
}


#[test]
fn test_sha256_as_crh_empty_param(){
    let expected = String::from("80a0d24abf3c8c3f47f3e6bcd6fc6e3b36bd1de50b6e721b2b0cb91a9376211f");
    let input = hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
    // let mut rng = ark_std::test_rng();

    // let hash_param = <sha256::Sha256 as CRHScheme>::setup(&mut rng).unwrap();
    let digest = <sha256::Sha256 as CRHScheme>::evaluate(&{}, input.clone()).unwrap();
    let digest_str = hex::encode(digest);
    assert_eq!(expected, digest_str);
    println!("{:?}", input);
}


#[test]
fn test_sha256_as_two_to_onec_crh(){
    use ark_crypto_primitives::crh::TwoToOneCRHScheme;

    let expected = String::from("80a0d24abf3c8c3f47f3e6bcd6fc6e3b36bd1de50b6e721b2b0cb91a9376211f");
    let left_input = hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
    let right_input = hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();

    let digest = <sha256::Sha256 as TwoToOneCRHScheme>::evaluate(&{}, left_input, right_input).unwrap();
    let digest_str = hex::encode(digest);
    assert_eq!(expected, digest_str);
}


#[test]
fn test_sha256_bytes(){
    let expected = String::from("80a0d24abf3c8c3f47f3e6bcd6fc6e3b36bd1de50b6e721b2b0cb91a9376211f");
    let input = hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
    // let mut rng = ark_std::test_rng();
    
    let digest = Sha256Bytes::digest(&input);
    let digest_str = hex::encode(digest);
    assert_eq!(expected, digest_str);
}

#[test]
fn test_sha256_bytes_all_zeros(){
    let expected = String::from("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    let input = vec![0u8; 64];
    // let mut rng = ark_std::test_rng();

    let sha256_bytes = Sha256Bytes;
    let digest = Sha256Bytes::digest(&input);
    // println!("{:?}", digest);
    let digest_str = hex::encode(digest);
    assert_eq!(expected, digest_str);
}



