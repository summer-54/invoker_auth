use std::io::Write;

use rand::CryptoRng;

use sequoia_openpgp::{
    self as pgp,
    parse::{
        Parse,
        stream::{DetachedVerifierBuilder, MessageLayer, VerificationHelper},
    },
    policy::Policy,
    serialize::stream::{Message, Signer},
};

pub use pgp::{Cert, cert::CertParser, policy};

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

pub struct Challenge {
    bytes: Box<[u8]>,
}

impl Challenge {
    pub fn generate(len: usize, rng: &mut impl CryptoRng) -> Self {
        let mut bytes = vec![0u8; len].into_boxed_slice();
        rng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: Box<[u8]>) -> Self {
        Self { bytes }
    }

    pub fn solve(&self, cert: &Cert, policy: &impl Policy) -> Result<Box<[u8]>> {
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

        let mut solution = Vec::<u8>::new();
        let mut sig = Signer::new(Message::new(&mut solution), key)?
            .detached()
            .build()?;

        sig.write_all(&self.bytes)?;
        sig.finalize()?;
        Ok(solution.into_boxed_slice())
    }

    pub fn bytes(&self) -> &Box<[u8]> {
        &self.bytes
    }

    pub fn check_solution(&self, solution: &[u8], cert: &Cert, policy: &impl Policy) -> Result<()> {
        let mut verifier = DetachedVerifierBuilder::from_bytes(solution)?.with_policy(
            policy,
            None,
            Helper(cert),
        )?;
        verifier.verify_bytes(&self.bytes)?;
        Ok(())
    }
}

#[test]
fn challendge_life_cycle() {
    let chg = Challenge::generate(100, &mut rand::rng());
    let bytes = chg.bytes().clone();

    dbg!("send to invoker");

    let chg = Challenge::from_bytes(bytes);
    let cert = Cert::from_file("tests/sec.key").unwrap();
    let solution = chg.solve(&cert, &policy::StandardPolicy::new()).unwrap();

    dbg!("send to manager");

    let cert = Cert::from_file("tests/pub.key").unwrap();
    chg.check_solution(&solution, &cert, &policy::StandardPolicy::new())
        .unwrap();
}
