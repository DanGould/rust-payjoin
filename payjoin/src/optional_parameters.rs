use std::borrow::Borrow;
use std::fmt;

use bitcoin::{Amount, FeeRate};
use log::warn;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug)]
#[cfg_attr(feature = "v2", derive(Deserialize, Serialize))]
pub(crate) struct Params {
    // version
    #[cfg_attr(
        feature = "v2",
        serde(skip_serializing_if = "skip_if_default_v", default = "default_v")
    )]
    pub v: usize,

    // disableoutputsubstitution
    #[cfg_attr(
        feature = "v2",
        serde(skip_serializing_if = "skip_if_false", default = "default_output_substitution")
    )]
    pub disable_output_substitution: bool,

    // maxadditionalfeecontribution, additionalfeeoutputindex
    #[cfg_attr(
        feature = "v2",
        serde(
            deserialize_with = "deserialize_additional_fee_contribution",
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_additional_fee_contribution"
        )
    )]
    pub additional_fee_contribution: Option<(Amount, usize)>,

    // minfeerate
    #[cfg_attr(
        feature = "v2",
        serde(
            deserialize_with = "from_sat_per_vb",
            skip_serializing_if = "skip_if_zero_rate",
            default = "default_min_feerate"
        )
    )]
    pub min_feerate: FeeRate,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            v: 1,
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
                    params.min_feerate = match feerate.parse::<f32>() {
                        Ok(fee_rate_sat_per_vb) => {
                            // TODO Parse with serde when rust-bitcoin supports it
                            let fee_rate_sat_per_kwu = fee_rate_sat_per_vb * 250.0_f32;
                            // since it's a minnimum, we want to round up
                            FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64)
                        }
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

fn deserialize_additional_fee_contribution<'de, D>(
    deserializer: D,
) -> Result<Option<(bitcoin::Amount, usize)>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AdditionalFeeContributionVisitor;

    impl<'de> Visitor<'de> for AdditionalFeeContributionVisitor {
        type Value = Option<(bitcoin::Amount, usize)>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("struct params")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut additional_fee_output_index: Option<usize> = None;
            let mut max_additional_fee_contribution: Option<bitcoin::Amount> = None;

            while let Some(key) = map.next_key()? {
                match key {
                    "additional_fee_output_index" => {
                        additional_fee_output_index = Some(map.next_value()?);
                    }
                    "max_additional_fee_contribution" => {
                        max_additional_fee_contribution =
                            Some(bitcoin::Amount::from_sat(map.next_value()?));
                    }
                    _ => {
                        // ignore other fields
                    }
                }
            }

            let additional_fee_contribution =
                match (max_additional_fee_contribution, additional_fee_output_index) {
                    (Some(amount), Some(index)) => Some((amount, index)),
                    (Some(_), None) | (None, Some(_)) => {
                        warn!(
                            "only one additional-fee parameter specified: {:?}, {:?}",
                            max_additional_fee_contribution, additional_fee_output_index
                        );
                        None
                    }
                    _ => None,
                };
            Ok(additional_fee_contribution)
        }
    }

    deserializer.deserialize_map(AdditionalFeeContributionVisitor)
}

fn default_v() -> usize { 2 }

fn default_output_substitution() -> bool { false }

fn default_min_feerate() -> FeeRate { FeeRate::ZERO }

// Function to determine whether to skip serializing a usize if it is 2 (the default)
fn skip_if_default_v(v: &usize) -> bool { *v == 2 }

// Function to determine whether to skip serializing a bool if it is false (the default)
fn skip_if_false(b: &bool) -> bool { !(*b) }

// Function to determine whether to skip serializing a FeeRate if it is ZERO (the default)
fn skip_if_zero_rate(rate: &FeeRate) -> bool {
    *rate == FeeRate::ZERO // replace with your actual comparison logic
}

fn from_sat_per_vb<'de, D>(deserializer: D) -> Result<FeeRate, D::Error>
where
    D: Deserializer<'de>,
{
    let fee_rate_sat_per_vb = f32::deserialize(deserializer)?;
    Ok(FeeRate::from_sat_per_kwu((fee_rate_sat_per_vb * 250.0_f32) as u64))
}

fn serialize_amount<S>(amount: &Amount, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(amount.to_sat())
}

fn serialize_additional_fee_contribution<S>(
    additional_fee_contribution: &Option<(Amount, usize)>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(None)?;
    if let Some((amount, index)) = additional_fee_contribution {
        map.serialize_entry("additional_fee_output_index", index)?;
        map.serialize_entry("max_additional_fee_contribution", &amount.to_sat())?;
    }
    map.end()
}

#[derive(Debug)]
pub(crate) enum Error {
    UnknownVersion,
    FeeRate(String),
    #[cfg(feature = "v2")]
    Json(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnknownVersion => write!(f, "unknown version"),
            Error::FeeRate(_) => write!(f, "could not parse feerate"),
            #[cfg(feature = "v2")]
            Error::Json(e) => write!(f, "could not parse json: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
