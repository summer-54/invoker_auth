use std::io::Write;

use rand::{CryptoRng, Rng};

use sequoia_openpgp::{
    self as pgp,
    parse::stream::{DetachedVerifierBuilder, MessageLayer, VerificationHelper},
    policy::Policy,
    serialize::stream::{Message, Signer},
};

pub use pgp::{Cert, parse::Parse, policy};

use anyhow::{Error, Result, anyhow};

struct Helper<'a>(&'a Cert);

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![self.0.clone()])
    }

    fn check(
        &mut self,
        structure: sequoia_openpgp::parse::stream::MessageStructure<'_>,
    ) -> sequoia_openpgp::Result<()> {
        if let Some(error) = structure.into_iter().find_map(|layer| {
            let MessageLayer::SignatureGroup { results } = layer else {
                return Option::<Error>::None;
            };
            results.into_iter().find_map(|result| {
                let Err(error) = result else {
                    return None;
                };
                Some(anyhow!(error.to_string()))
            })
        }) {
            Err(error.into())
        } else {
            Ok(())
        }
    }
}

pub struct Challenge(Box<[u8]>);
pub struct Solution(Box<[u8]>);

impl From<&[u8]> for Challenge {
    fn from(bytes: &[u8]) -> Self {
        Self(Box::from(bytes))
    }
}

impl std::ops::Deref for Challenge {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl From<&[u8]> for Solution {
    fn from(bytes: &[u8]) -> Self {
        Self(Box::from(bytes))
    }
}

impl std::ops::Deref for Solution {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl Challenge {
    pub fn generate<R: CryptoRng + Rng>(len: usize, rng: &mut R) -> Self {
        let mut bytes = vec![0u8; len].into_boxed_slice();
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn solve(&self, cert: &Cert, policy: &impl Policy) -> Result<Solution> {
        let key = cert
            .keys()
            .supported()
            .secret()
            .with_policy(policy, None)
            .for_signing()
            .for_authentication()
            .next()
            .ok_or(Error::msg("valid key not founded"))?
            .key()
            .clone()
            .into_keypair()?;

        let mut bytes = Vec::<u8>::new();
        let mut sig = Signer::new(Message::new(&mut bytes), key)?
            .detached()
            .build()?;

        sig.write_all(&self.0)?;
        sig.finalize()?;
        Ok(Solution(bytes.into()))
    }
}

impl Solution {
    pub fn verify(&self, challenge: &Challenge, cert: &Cert, policy: &impl Policy) -> Result<()> {
        let verifier = DetachedVerifierBuilder::from_bytes(&self.0)?;
        let mut verifier = verifier.with_policy(policy, None, Helper(cert))?;
        verifier.verify_bytes(&**challenge)?;
        Ok(())
    }
}

#[test]
fn challendge_life_cycle() {
    use std::{io::Read, str::FromStr};
    let chg = Challenge::generate(10, &mut rand::rng());
    let bytes: Box<[u8]> = Box::from(&*chg);

    dbg!("send to invoker");

    let chg = Challenge::from(&*bytes);
    let cert = Cert::from_file("tests/sec.key").unwrap();
    let solution = chg.solve(&cert, &policy::StandardPolicy::new()).unwrap();
    let bytes: Box<[u8]> = Box::from(&*solution);

    dbg!("send to manager");

    let solution = Solution::from(&*bytes);
    let mut ct = String::new();
    std::fs::File::open("tests/pub.key")
        .unwrap()
        .read_to_string(&mut ct)
        .unwrap();
    let cert = Cert::from_str(&*ct).unwrap();
    solution
        .verify(&chg, &cert, &policy::StandardPolicy::new())
        .unwrap();
}
