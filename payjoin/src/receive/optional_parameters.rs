use alloc::borrow::Borrow;
use core::fmt;

use log::warn;

use crate::fee_rate::FeeRate;
use crate::prelude::*;

#[derive(Debug)]
pub(crate) struct Params {
    // version
    // v: usize,
    // disableoutputsubstitution
    pub disable_output_substitution: bool,
    // maxadditionalfeecontribution, additionalfeeoutputindex
    pub additional_fee_contribution: Option<(bitcoin::Amount, usize)>,
    // minfeerate
    pub min_feerate: FeeRate,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            disable_output_substitution: false,
            additional_fee_contribution: None,
            min_feerate: FeeRate::ZERO,
        }
    }
}

impl Params {
    #[cfg(feature = "receive")]
    pub fn from_query_pairs<K, V, I>(pairs: I) -> Result<Self, Error>
    where
        I: Iterator<Item = (K, V)>,
        K: Borrow<str> + Into<String>,
        V: Borrow<str> + Into<String>,
    {
        let mut params = Params::default();

        let mut additional_fee_output_index = None;
        let mut max_additional_fee_contribution = None;

        for (k, v) in pairs {
            match (k.borrow(), v.borrow()) {
                ("v", v) =>
                    if v != "1" {
                        return Err(Error::UnknownVersion);
                    },
                ("additionalfeeoutputindex", index) =>
                    additional_fee_output_index = match index.parse::<usize>() {
                        Ok(index) => Some(index),
                        Err(_error) => {
                            warn!(
                                "bad `additionalfeeoutputindex` query value '{}': {}",
                                index, _error
                            );
                            None
                        }
                    },
                ("maxadditionalfeecontribution", fee) =>
                    max_additional_fee_contribution =
                        match bitcoin::Amount::from_str_in(fee, bitcoin::Denomination::Satoshi) {
                            Ok(contribution) => Some(contribution),
                            Err(_error) => {
                                warn!(
                                    "bad `maxadditionalfeecontribution` query value '{}': {}",
                                    fee, _error
                                );
                                None
                            }
                        },
                ("minfeerate", feerate) =>
                    params.min_feerate = match feerate.parse::<u64>() {
                        Ok(rate) => FeeRate::from_sat_per_vb(rate)
                            .ok_or_else(|| Error::FeeRate(rate.to_string()))?,
                        Err(e) => return Err(Error::FeeRate(e.to_string())),
                    },
                ("disableoutputsubstitution", v) =>
                    params.disable_output_substitution = v == "true",
                _ => (),
            }
        }

        match (max_additional_fee_contribution, additional_fee_output_index) {
            (Some(amount), Some(index)) =>
                params.additional_fee_contribution = Some((amount, index)),
            (Some(_), None) | (None, Some(_)) => {
                warn!("only one additional-fee parameter specified: {:?}", params);
            }
            _ => (),
        }

        log::debug!("parsed optional parameters: {:?}", params);
        Ok(params)
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    UnknownVersion,
    FeeRate(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnknownVersion => write!(f, "unknown version"),
            Error::FeeRate(_) => write!(f, "could not parse feerate"),
        }
    }
}

impl crate::StdError for Error {
    fn source(&self) -> Option<&(dyn crate::StdError + 'static)> { None }
}
