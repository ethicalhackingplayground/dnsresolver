// Import the necessary libraries
use async_std::net::TcpStream; // Provides functionality for TCP networking
                               // Rate limiting library
use reqwest::{header::HeaderValue, redirect, Method, Request}; // HTTP client library
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    time::Duration,
}; // Standard library modules for error handling, networking, and time
use tokio::sync::mpsc;

// Import the `AsyncResolver` struct from the `hickory_resolver` crate
use hickory_resolver::AsyncResolver;

use crate::{Job, JobResult};

// Overall, this function is responsible for running a resolver asynchronously by receiving `Job` objects from the `rx` receiver and using the `resolver` to handle DNS resolution.
pub async fn run_resolver(
    tx: mpsc::Sender<JobResult>,
    rx: spmc::Receiver<Job>,
    resolver: AsyncResolver<
        hickory_resolver::name_server::GenericConnector<
            hickory_resolver::name_server::TokioRuntimeProvider,
        >,
    >,
    vhost: bool,
    out: &str,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    //no certs
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(redirect::Policy::limited(10))
        .timeout(Duration::from_secs(3))
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    while let Ok(job) = rx.recv() {
        // Receive a job from the channel and assign it to the `job` variable

        let job_host: String = job.host.unwrap();
        // Extract the `host` field from the `job` and assign it to the `job_host` variable.
        // The `unwrap()` method is used here assuming that the `host` field always has a value and is not `None`.
        // If `host` is `None`, it will panic.

        let job_ports = job.ports.unwrap();
        // Extract the `ports` field from the `job` and assign it to the `job_ports` variable.
        // Similar to `job_host`, it assumes that the `ports` field always has a value and is not `None`.
        // If `ports` is `None`, it will panic.

        // Clone the `job_ports` variable and convert it to a string, then assign it to the `ports` variable.
        // This is done to avoid modifying the original `job_ports` variable.
        let ports = job_ports.clone().to_string();

        // probe for open ports and perform dns resolution
        if ports.is_empty() {
            // Lookup the IP addresses associated with a name.
            // The final dot forces this to be an FQDN, otherwise the search rules as specified
            // in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
            let response = match resolver.lookup_ip(job_host.as_str().to_string()).await {
                Ok(r) => r,
                Err(_) => {
                    // If the DNS lookup fails, return early
                    continue;
                }
            };

            // There can be many addresses associated with the name,
            // this can return IPv4 and/or IPv6 addresses
            let address = match response.iter().next() {
                Some(a) => a,
                None => continue,
            };

            if address.is_ipv4() {
                println!("{}", job_host);
            }
        } else {
            // Split the `ports` string by commas, convert each port to a string,
            // and collect them into a vector of strings (`Vec<String>`).
            // The resulting vector is assigned to the `ports_array` variable.
            let ports_array = ports
                .split(",")
                .map(|port| port.to_string())
                .collect::<Vec<_>>();

            for port in ports_array {
                let host = job_host.clone().to_string();

                // Lookup the IP addresses associated with a name.
                // The final dot forces this to be an FQDN, otherwise the search rules as specified
                // in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
                let response = match resolver.lookup_ip(job_host.as_str().to_string()).await {
                    Ok(r) => r,
                    Err(_) => {
                        // If the DNS lookup fails, return early
                        continue;
                    }
                };

                // There can be many addresses associated with the name,
                // this can return IPv4 and/or IPv6 addresses
                let address = match response.iter().next() {
                    Some(a) => a,
                    None => continue,
                };

                if address.is_ipv4() {
                    let timeout = Duration::from_millis(100);
                    let port_int = match port.parse::<u16>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    let (host_with_port, ip_str) =
                        check_port(address, port_int, host, timeout).await;

                    if vhost {
                        // The above code is checking if a virtual host (vhost) is enabled. If it is enabled, it
                        let domain = host_with_port.clone();
                        
                        let ip_url = match reqwest::Url::parse(&ip_str.to_string()) {
                            Ok(u) => u,
                            Err(_) => continue,
                        };

                        // Build a request
                        let mut request = Request::new(Method::GET, ip_url);

                        let url = match reqwest::Url::parse(&host_with_port) {
                            Ok(u) => u,
                            Err(_) => continue,
                        };
                        let host_value = match url.domain() {
                            Some(d) => d,
                            None => continue,
                        };

                        // Replace the Host header
                        request.headers_mut().insert(
                            reqwest::header::HOST,
                            HeaderValue::from_str(host_value).unwrap(),
                        );

                        // Make a request with the modified headers
                        let response = match client.execute(request).await {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                        if response.status().as_u16() != 404 {
                            // Print the domain and IP address
                            println!("\n\t{} belongs to -> {}", domain, address.to_string());
                            let job = JobResult {
                                domain: domain,
                                ip: address.to_string(),
                                outdir: out.to_owned(),
                            };

                            if let Err(_) = tx.send(job).await {
                                continue;
                            }
                        }
                    } else {
                        println!("{}", host_with_port);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Asynchronously checks if a given port is open on a given IP address.
/// Returns a tuple containing the HTTP and IP addresses.
async fn check_port(
    ip_addr: IpAddr,   // The IP address to check
    port: u16,         // The port to check
    host: String,      // The host name
    timeout: Duration, // The timeout duration for the TCP connection
) -> (String, String) {
    let port_str = port.to_string(); // Convert the port number to a string
    let https_with_port = String::from(format!("{}{}:{}", "https://", host, port_str)); // Construct the HTTPS URL with the port
    let http_with_port = String::from(format!("{}{}:{}", "http://", host, port_str)); // Construct the HTTP URL with the port
    if port_str == "80" {
        let socket_address = SocketAddr::new(ip_addr.clone(), port); // Create a socket address using the IP address and port

        // If the TCP connection is successful, print the HTTP URL with the port
        let ip = String::from(format!("{}{}:{}", "http://", ip_addr.to_string(), port));

        match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
            Ok(Ok(_)) => {
                return (http_with_port, ip); // Return the HTTP URL and IP address
            }
            _ => {
                // If the TCP connection fails, return early
                return ("".to_string(), "".to_string()); // Return empty strings
            }
        }
    }else if port_str == "443" {
        // If the TCP connection is successful, print the HTTPS URL with the port
        let ip = String::from(format!("{}{}:{}", "https://", ip_addr.to_string(), port));

        let socket_address = SocketAddr::new(ip_addr.clone(), port); // Create a socket address using the IP address and port

        match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
            Ok(Ok(_)) => {
                return (https_with_port, ip); // Return the HTTPS URL and IP address
            }
            _ => {
                // If the TCP connection fails, return early
                return ("".to_string(), "".to_string()); // Return empty strings
            }
        }
    }else{
        // If the TCP connection is successful, print the HTTPS URL with the port
        let ip = String::from(format!("{}{}:{}", "https://", ip_addr.to_string(), port));

        let socket_address = SocketAddr::new(ip_addr.clone(), port); // Create a socket address using the IP address and port

        match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
            Ok(Ok(_)) => {
                return (https_with_port, ip); // Return the HTTPS URL and IP address
            }
            _ => {
                // If the TCP connection fails, return early
                return ("".to_string(), "".to_string()); // Return empty strings
            }
        }
    }
}
