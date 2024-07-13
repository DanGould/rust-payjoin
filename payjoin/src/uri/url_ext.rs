use std::str::FromStr;

use percent_encoding::{AsciiSet, PercentDecodeError, CONTROLS};
use url::Url;

use crate::OhttpKeys;

/// Parse and set fragment parameters from `&pj=` URI parameter URLs
pub(crate) trait UrlExt {
    fn ohttp(&self) -> Result<Option<OhttpKeys>, PercentDecodeError>;
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>) -> Result<(), PercentDecodeError>;
    fn exp(&self) -> Result<Option<std::time::SystemTime>, PercentDecodeError>;
    fn set_exp(&mut self, exp: Option<std::time::SystemTime>) -> Result<(), PercentDecodeError>;
}

// Characters '=' and '&' conflict with BIP21 URI parameters and must be percent-encoded
const BIP21_CONFLICTING: &AsciiSet = &CONTROLS.add(b'=').add(b'&');

impl UrlExt for Url {
    /// Retrieve the ohttp parameter from the URL fragment
    fn ohttp(&self) -> Result<Option<OhttpKeys>, PercentDecodeError> {
        get_param(self, "ohttp=", |value| OhttpKeys::from_str(value).ok())
    }

    /// Set the ohttp parameter in the URL fragment
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>) -> Result<(), PercentDecodeError> {
        set_param(self, "ohttp=", ohttp.map(|o| o.to_string()))
    }

    /// Retrieve the exp parameter from the URL fragment
    fn exp(&self) -> Result<Option<std::time::SystemTime>, PercentDecodeError> {
        get_param(self, "exp=", |value| {
            value
                .parse::<u64>()
                .ok()
                .map(|timestamp| std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp))
        })
    }

    /// Set the exp parameter in the URL fragment
    fn set_exp(&mut self, exp: Option<std::time::SystemTime>) -> Result<(), PercentDecodeError> {
        let exp_str = exp.map(|e| {
            match e.duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => duration.as_secs().to_string(),
                Err(_) => "0".to_string(), // Handle times before Unix epoch by setting to "0"
            }
        });
        set_param(self, "exp=", exp_str)
    }
}

fn get_param<F, T>(url: &Url, prefix: &str, parse: F) -> Result<Option<T>, PercentDecodeError>
where
    F: Fn(&str) -> Option<T>,
{
    if let Some(fragment) = url.fragment() {
        let decoded_fragment = percent_encoding::percent_decode_str(fragment)?.decode_utf8_lossy();
        for param in decoded_fragment.split('&') {
            if let Some(value) = param.strip_prefix(prefix) {
                return Ok(parse(value));
            }
        }
    }
    Ok(None)
}

fn set_param(url: &mut Url, prefix: &str, value: Option<String>) -> Result<(), PercentDecodeError> {
    let fragment = url.fragment().unwrap_or("");
    let mut fragment = percent_encoding::percent_decode_str(fragment)?.decode_utf8_lossy();

    if let Some(start) = fragment.find(prefix) {
        let end = fragment[start..].find('&').map_or(fragment.len(), |i| start + i);
        fragment.to_mut().replace_range(start..end, "");
        if fragment.ends_with('&') {
            fragment.to_mut().pop();
        }
    }

    if let Some(value) = value {
        let new_param = format!("{}{}", prefix, value);
        if !fragment.is_empty() {
            fragment.to_mut().push('&');
        }
        fragment.to_mut().push_str(&new_param);
    }

    let encoded_fragment =
        percent_encoding::utf8_percent_encode(&fragment, BIP21_CONFLICTING).to_string();
    url.set_fragment(if encoded_fragment.is_empty() { None } else { Some(&encoded_fragment) });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Uri, UriExt};

    #[test]
    fn test_ohttp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let ohttp_keys =
            OhttpKeys::from_str("AQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM").unwrap();
        let _ = url.set_ohttp(Some(ohttp_keys.clone()));
        assert_eq!(
            url.fragment(),
            Some("ohttp%3DAQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM")
        );

        let retrieved_ohttp = url.ohttp().unwrap();
        assert_eq!(retrieved_ohttp, Some(ohttp_keys));

        let _ = url.set_ohttp(None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_exp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let exp_time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1720547781);
        let _ = url.set_exp(Some(exp_time));
        assert_eq!(url.fragment(), Some("exp%3D1720547781"));

        let retrieved_exp = url.exp().unwrap();
        assert_eq!(retrieved_exp, Some(exp_time));

        let _ = url.set_exp(None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_invalid_v2_url_fragment_on_bip21() {
        // fragment is not percent encoded so `&ohttp=` is parsed as a query parameter, not a fragment parameter
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=https://example.com\
                   #exp=1720547781&ohttp=AQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM";
        let uri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(uri.extras.endpoint().ohttp().unwrap().is_none());
    }

    #[test]
    fn test_valid_v2_url_fragment_on_bip21() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=https://example.com\
                   #ohttp%3DAQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM%26exp%3D1720547781";
        let uri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(uri.extras.endpoint().ohttp().unwrap().is_some());
    }
}
