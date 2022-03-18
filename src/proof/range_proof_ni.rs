use ring::digest::{Context, SHA256};
use std::borrow::Borrow;

use arithimpl::traits::*;
use core::*;
use proof::correct_key::CorrectKeyProofError;
use proof::range_proof::{ChallengeBits, EncryptedPairs, Proof};
use {BigInt, EncryptionKey, Paillier, RawCiphertext};
#[cfg(test)]
const RANGE_BITS: usize = 256; //for elliptic curves with 256bits for example

/// Zero-knowledge range proof that a value x<q/3 lies in interval [0,q].
///
/// The verifier is given only c = ENC(ek,x).
/// The prover has input x, dk, r (randomness used for calculating c)
/// It is assumed that q is known to both.
///
/// References:
/// - Appendix A in [Lindell'17](https://eprint.iacr.org/2017/552)
/// - Section 1.2.2 in [Boudot '00](https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf)
///
/// This is a non-interactive version of the proof, using Fiat Shamir Transform and assuming Random Oracle Model
pub trait RangeProofNI {
    fn prover(
        ek: &EncryptionKey,
        range: &BigInt,
        secret_x: &BigInt,
        secret_r: &BigInt,
    ) -> (EncryptedPairs, ChallengeBits, Proof);

    fn verifier(
        ek: &EncryptionKey,
        e: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        z: &Proof,
        range: &BigInt,
        cipher_x: RawCiphertext,
    ) -> Result<(), CorrectKeyProofError>;
}

impl RangeProofNI for Paillier {
    fn prover(
        ek: &EncryptionKey,
        range: &BigInt,
        secret_x: &BigInt,
        secret_r: &BigInt,
    ) -> (EncryptedPairs, ChallengeBits, Proof) {
        use proof::RangeProof;
        let (encrypted_pairs, data_randomness_pairs) =
            Paillier::generate_encrypted_pairs(ek, range);
        let (c1, c2) = (encrypted_pairs.c1, encrypted_pairs.c2); // TODO[Morten] fix temporary hack

        // TODO[Morten] why only the first element?
        let mut vec: Vec<BigInt> = Vec::new();
        vec.push(c1[0].clone());
        vec.push(c2[0].clone());
        let e = ChallengeBits::from(compute_digest(vec.iter()));

        //assuming digest length > STATISTICAL_ERROR_FACTOR

        let proof =
            Paillier::generate_proof(ek, secret_x, secret_r, &e, range, &data_randomness_pairs);

        (EncryptedPairs { c1, c2 }, e, proof)
    }

    fn verifier(
        ek: &EncryptionKey,
        e: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        proof: &Proof,
        range: &BigInt,
        cipher_x: RawCiphertext,
    ) -> Result<(), CorrectKeyProofError> {
        use proof::RangeProof;
        <Paillier as RangeProof>::verifier_output(ek, e, encrypted_pairs, proof, range, cipher_x)
    }
}

fn compute_digest<IT>(values: IT) -> Vec<u8>
where
    IT: Iterator,
    IT::Item: Borrow<BigInt>,
{
    let mut digest = Context::new(&SHA256);
    for value in values {
        // covert bigint to hex-string for stupid javascript
        let bytes: Vec<u8> = value.borrow().to_str_radix(16).as_bytes().to_vec();
        digest.update(&bytes);
    }
    digest.finish().as_ref().into()
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use super::*;
    use test::Bencher;
    use rustc_serialize::hex::ToHex;
    use serde_json::Value::String;
    use traits::*;
    use {Keypair, RawPlaintext};
    use Randomness;
    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair { p, q }
    }
    #[test]
    fn test_sha256(){
        let mut vec: Vec<&str> = Vec::new();
        vec.push("Message Part 1");
        vec.push("Message Part 2");
        vec.push("Message Part 3");
        let mut digest = Context::new(&SHA256);
        for value in vec {
            let bytes: Vec<u8> = value.borrow().into();
            digest.update(&bytes);
        }
        let res:Vec<u8> = digest.finish().as_ref().into();
        let hex = res.to_hex();
        println!("{}", hex);
    }
    #[test]
    fn test_compute_digest(){
        let mut vec: Vec<BigInt> = Vec::new();
        vec.push(BigInt::from(123123123));
        vec.push(BigInt::from(123123123));
        vec.push(BigInt::from(123123123));
        let res = compute_digest(vec.iter());
        let hex = res.to_hex();
        println!("{}", hex);
    }
    #[test]
    fn test_prover() {
        let (ek, _dk) = test_keypair().keys();
        let range = BigInt::sample(RANGE_BITS);
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::sample_below(&range);
        let (_encrypted_pairs, _challenge, _proof) =
            Paillier::prover(&ek, &range, &secret_x, &secret_r);
    }

    #[test]
    fn test_verifier_for_correct_proof() {
        let (ek, _dk) = test_keypair().keys();
        let range = BigInt::sample(RANGE_BITS);
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3i32)));
        let cipher_x = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(&secret_x),
            &Randomness(secret_r.clone()),
        );
        let (encrypted_pairs, challenge, proof) =
            Paillier::prover(&ek, &range, &secret_x, &secret_r);
        let ek_b = bincode::serialize(&ek).unwrap();
        let mut file = std::fs::File::create("ek.bin").expect("create failed");
        file.write_all(ek_b.as_slice());
        let challenge_b = bincode::serialize(&challenge).unwrap();
        let mut file = std::fs::File::create("challenge.bin").expect("create failed");
        file.write_all(challenge_b.as_slice());
        let encrypted_pairs_b = bincode::serialize(&encrypted_pairs).unwrap();
        let mut file = std::fs::File::create("encrypted_pairs.bin").expect("create failed");
        file.write_all(encrypted_pairs_b.as_slice());
        let proof_b = bincode::serialize(&proof).unwrap();
        let mut file = std::fs::File::create("proof.bin").expect("create failed");
        file.write_all(proof_b.as_slice());
        let range_b = Vec::<u8>::from(&range);
        //let json =bincode::serialize(&v8).unwrap();
        let mut file = std::fs::File::create("range.bin").expect("create failed");
        file.write_all(range_b.as_slice());
        let cipher= cipher_x.clone();
        //let json = bincode::serialize(&Vec::<u8>::from(&cipher.0.into_owned())).unwrap();
        let mut file = std::fs::File::create("cipher.bin").expect("create failed");
        //file.write_all(&Vec::<u8>::from(&cipher.0.into_owned()));
        let result =
            Paillier::verifier(&ek, &challenge, &encrypted_pairs, &proof, &range, cipher_x);
        println!("let ek={:?};",&ek_b);
        println!("let challenge={:?};",&challenge_b);
        println!("let encrypted_pairs={:?};",&encrypted_pairs_b);
        println!("let proof={:?};",&proof_b);
        println!("let range={:?};",&range_b);
        println!("let cipher={:?};",&Vec::<u8>::from(&cipher.0.into_owned()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verifier_for_incorrect_proof() {
        let (ek, _dk) = test_keypair().keys();
        let range = BigInt::sample(RANGE_BITS);
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::sample_range(
            &(BigInt::from(100i32) * &range),
            &(BigInt::from(10000i32) * &range),
        );
        let cipher_x = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(&secret_x),
            &Randomness(secret_r.clone()),
        );
        let (encrypted_pairs, challenge, proof) =
            Paillier::prover(&ek, &range, &secret_x, &secret_r);
        let result =
            Paillier::verifier(&ek, &challenge, &encrypted_pairs, &proof, &range, cipher_x);
        assert!(result.is_err());
    }

    #[bench]
    fn bench_range_proof(b: &mut Bencher) {
        // TODO: bench range for 256bit range.
        b.iter(|| {
            let (ek, _dk) = test_keypair().keys();
            let range = BigInt::sample(RANGE_BITS);
            let secret_r = BigInt::sample_below(&ek.n);
            let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
            let cipher_x = Paillier::encrypt_with_chosen_randomness(
                &ek,
                RawPlaintext::from(&secret_x),
                &Randomness(secret_r.clone()),
            );
            let (encrypted_pairs, challenge, proof) =
                Paillier::prover(&ek, &range, &secret_x, &secret_r);
            let result =
                Paillier::verifier(&ek, &challenge, &encrypted_pairs, &proof, &range, cipher_x.clone());
            assert_eq!(result.is_ok(), true);
        });
    }

}
