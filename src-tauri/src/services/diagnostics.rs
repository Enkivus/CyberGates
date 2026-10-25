use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::models::{now_rfc3339, HostDiagnostic, TlsDiagnostic};

const MAX_DNS_ADDRESSES: usize = 16;
const MAX_TLS_ATTEMPTS: usize = 4;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn diagnose_host(input: &str) -> AppResult<HostDiagnostic> {
    let host = validate_host(input)?;
    let (addresses, addresses_truncated) = resolve_host(&host)?;
    let tls = probe_tls(&host, &addresses);

    Ok(HostDiagnostic {
        host,
        resolved_at: now_rfc3339(),
        addresses: addresses.iter().map(ToString::to_string).collect(),
        addresses_truncated,
        tls,
        scope_note: "DNS uses the operating system's configured resolver. TLS tries at most 4 resolved addresses on TCP port 443, with bounded connect and handshake timeouts, and validates the certificate chain and host name using the bundled Mozilla root set. No HTTP request or application data is sent.".to_string(),
    })
}

fn validate_host(input: &str) -> AppResult<String> {
    let host = input.trim();
    if host.is_empty() || host.len() > 253 {
        return Err(AppError::Validation(
            "host must contain between 1 and 253 characters".to_string(),
        ));
    }
    if host.chars().any(|c| c.is_control() || c.is_whitespace())
        || host.contains(['/', '\\', '@', ':', '?', '#'])
    {
        if host.parse::<IpAddr>().is_err() {
            return Err(AppError::Validation(
                "enter a host name or IP address without a URL scheme, port, or path".to_string(),
            ));
        }
    }

    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(address.to_string());
    }

    let normalized = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return Err(AppError::Validation("invalid host name".to_string()));
    }
    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AppError::Validation(
                "host name must use valid ASCII DNS labels (use punycode for IDNs)".to_string(),
            ));
        }
    }
    Ok(normalized)
}

fn resolve_host(host: &str) -> AppResult<(Vec<SocketAddr>, bool)> {
    let mut resolved = Vec::new();
    let mut truncated = false;
    if let Ok(ip) = host.parse::<IpAddr>() {
        resolved.push(SocketAddr::new(ip, 443));
    } else {
        let lookup = (host, 443).to_socket_addrs().map_err(|err| {
            AppError::Internal(format!(
                "system DNS lookup failed: {}",
                short_error(&err.to_string())
            ))
        })?;
        for address in lookup {
            if !resolved
                .iter()
                .any(|existing: &SocketAddr| existing.ip() == address.ip())
            {
                if resolved.len() == MAX_DNS_ADDRESSES {
                    truncated = true;
                    break;
                }
                resolved.push(address);
            }
        }
    }
    if resolved.is_empty() {
        return Err(AppError::Internal(
            "system DNS lookup returned no addresses".to_string(),
        ));
    }
    Ok((resolved, truncated))
}

fn probe_tls(host: &str, addresses: &[SocketAddr]) -> TlsDiagnostic {
    let mut last_error = "no TLS connection could be established".to_string();
    for address in addresses.iter().take(MAX_TLS_ATTEMPTS) {
        match connect_and_handshake(host, *address) {
            Ok(mut tls) => {
                tls.verified = true;
                tls.peer_address = Some(address.to_string());
                return tls;
            }
            Err(error) => last_error = short_error(&error),
        }
    }
    TlsDiagnostic {
        verified: false,
        peer_address: None,
        protocol: None,
        cipher_suite: None,
        certificate_chain_length: 0,
        leaf_sha256: None,
        error: Some(last_error),
    }
}

fn connect_and_handshake(host: &str, address: SocketAddr) -> Result<TlsDiagnostic, String> {
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .map_err(|err| format!("TCP connection failed: {}", err))?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string())
            .map_err(|_| "invalid TLS server name".to_string())?,
    };
    let mut connection = ClientConnection::new(config.into(), server_name)
        .map_err(|err| format!("could not initialize TLS: {err}"))?;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    while connection.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("TLS handshake timed out".to_string());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|err| err.to_string())?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|err| err.to_string())?;
        connection
            .complete_io(&mut stream)
            .map_err(|err| format!("TLS verification failed: {err}"))?;
    }

    let certificates = connection.peer_certificates().unwrap_or_default();
    let leaf_sha256 = certificates
        .first()
        .map(|certificate| hex::encode(Sha256::digest(certificate.as_ref())));
    Ok(TlsDiagnostic {
        verified: true,
        peer_address: Some(address.to_string()),
        protocol: connection
            .protocol_version()
            .map(|version| format!("{version:?}")),
        cipher_suite: connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite())),
        certificate_chain_length: certificates.len(),
        leaf_sha256,
        error: None,
    })
}

fn short_error(message: &str) -> String {
    let sanitized: String = message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(240)
        .collect();
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_dns_names_and_accepts_ip_literals() {
        assert_eq!(validate_host(" Example.COM. ").unwrap(), "example.com");
        assert_eq!(validate_host("192.0.2.4").unwrap(), "192.0.2.4");
        assert_eq!(validate_host("2001:db8::1").unwrap(), "2001:db8::1");
    }

    #[test]
    fn rejects_url_syntax_and_invalid_dns_labels() {
        for invalid in [
            "https://example.com",
            "example.com:8443",
            "user@example.com",
            "example.com/path",
            "-bad.example",
            "bad..example",
            "bad_name.example",
        ] {
            assert!(validate_host(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn bounds_reported_resolver_errors() {
        assert!(short_error(&"x".repeat(1000)).len() <= 240);
        assert!(!short_error("bad\ninput").contains('\n'));
    }
}
