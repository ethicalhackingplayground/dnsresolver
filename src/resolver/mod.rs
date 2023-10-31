// Import the necessary libraries
use async_std::net::TcpStream;
use distance::sift3;
use reqwest::{header::HeaderValue, redirect, Method, Request}; // Import the `TcpStream` struct from the `async_std::net` module to provide functionality for TCP networking
use std::{
    error::Error, // Import the `Error` trait from the `std::error` module for error handling
    net::{IpAddr, SocketAddr}, // Import the `IpAddr` and `SocketAddr` structs from the `std::net` module for networking
    time::Duration,
}; // Import various modules from the standard library for error handling, networking, and time
use tokio::sync::mpsc; // Import the `mpsc` module from the `tokio::sync` crate for multi-producer, single-consumer communication primitives

// Import the `AsyncResolver` struct from the `hickory_resolver` crate
use hickory_resolver::AsyncResolver;

use crate::{waf, Job, JobResult}; // Import the `Job` and `JobResult` types from the current crate

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
    validation_level: f32,
    check_localhost: bool,
    show_unresolved: bool,
    outdir: String,
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
        let dns_domain = job.unresolved_host.unwrap();

        // Extract the `host` field from the `job` and assign it to the `job_host` variable.
        // The `unwrap()` method is used here assuming that the `host` field always has a value and is not `None`.
        // If `host` is `None`, it will panic.
        let job_host: String = job.host.unwrap();

        // Extract the `ports` field from the `job` and assign it to the `job_ports` variable.
        // Similar to `job_host`, it assumes that the `ports` field always has a value and is not `None`.
        // If `ports` is `None`, it will panic.
        let job_ports = job.ports.unwrap();

        // Clone the `job_ports` variable and convert it to a string, then assign it to the `ports` variable.
        // This is done to avoid modifying the original `job_ports` variable.
        let mut ports = job_ports.clone().to_string();

        // Clone the `outdir` variable and convert it to a string, then assign it to the `out` variable.
        // This is done to avoid modifying the original `outdir` variable.
        let out = outdir.as_str().clone();

        // probe for open ports and perform dns resolution
        if ports.is_empty() && !vhost && show_unresolved {
            // Check if the flag 'show_unresolved' is true
            if show_unresolved {
                // Try to lookup the IP address for the 'job_host' using the 'resolver' object
                if let Err(_) = resolver.lookup_ip(job_host.as_str().to_string()).await {
                    // If the lookup fails, append the 'job_host' to the 'unresolved_host' string
                    println!("{}", &job_host.to_string());
                };
            } else {
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
            }
        } else {
            if vhost {
                ports = "80,443".to_owned();
            }
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
                if let Ok(response) = resolver.lookup_ip(job_host.as_str().to_string()).await {
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

                        // Declare variables to store the results of the `check_port` function
                        let (host_with_port, ip_str) =
                            check_port(address, port_int, host, timeout).await;

                        // Check if the `vhost` flag is set to true
                        if vhost {
                            if check_localhost {
                                let main_page = ip_str.clone();
                                let ip_host = main_page.clone();
                                let dns_domain = "localhost";

                                // Parse the job IP address into a URL
                                let ip_url = match reqwest::Url::parse(&ip_str.to_string()) {
                                    // If parsing succeeds, assign the parsed URL to 'ip_url'
                                    Ok(u) => u,
                                    // If parsing fails, continue to the next iteration of the loop
                                    Err(_) => {
                                        continue;
                                    }
                                };

                                // Build a request with the GET method and the parsed URL
                                let mut request = Request::new(Method::GET, ip_url);

                                // If false, insert a 'HOST' header with the value 'unresolved_domain' into the request headers
                                // The 'unresolved_domain' variable is assumed to be defined elsewhere in the code
                                // This is to ensure that the request is sent to the specified domain
                                request.headers_mut().insert(
                                    reqwest::header::HOST,
                                    HeaderValue::from_str("localhost").unwrap(),
                                );

                                // Create a clone of the `request` object and assign it to `request_clone`
                                let request_clone = match request.try_clone() {
                                    // If the `try_clone()` method returns `Some`, which means the cloning was successful,
                                    // assign the cloned object to `rc`
                                    Some(rc) => rc,
                                    // If the `try_clone()` method returns `None`, which means the cloning failed,
                                    // skip to the next iteration of the loop
                                    None => continue,
                                };

                                // Check if a Web Application Firewall (WAF) is detected for the specified `ip_host` with `request_clone`
                                if waf::detect_waf(ip_host, request_clone).await {
                                    // If a WAF is detected, skip to the next iteration of the loop
                                    continue;
                                }

                                // Make a request with the modified headers using the 'client' object
                                let response = match client.execute(request).await {
                                    // If the request is successful, assign the response to 'response'
                                    Ok(r) => r,
                                    // If there's an error, continue to the next iteration of the loop
                                    Err(_) => continue,
                                };
                                let content_length = match response.content_length() {
                                    // Check if the response has a content length
                                    Some(cl) => cl,
                                    // If the response doesn't have a content length, skip to the next iteration
                                    None => continue,
                                };

                                let status_code = response.status().as_u16().to_string();

                                let response_body = match response.text().await {
                                    // Build the GET request
                                    Ok(r) => r,
                                    // If there's an error building the request, skip to the next iteration
                                    Err(_) => continue,
                                };

                                // Create a new GET request to the main_page
                                let get = client.get(main_page);

                                let req = match get.build() {
                                    // Build the GET request
                                    Ok(r) => r,
                                    // If there's an error building the request, skip to the next iteration
                                    Err(_) => continue,
                                };

                                // Execute the GET request
                                let response2 = match client.execute(req).await {
                                    // If the request is successful, store the response
                                    Ok(r) => r,
                                    // If there's an error executing the request, skip to the next iteration
                                    Err(_) => continue,
                                };

                                let main_response_body = match response2.text().await {
                                    // Build the GET request
                                    Ok(r) => r,
                                    // If there's an error building the request, skip to the next iteration
                                    Err(_) => continue,
                                };

                                // Calculate the SIFT3 distance between the string representations of `main_content_length` and `content_length`
                                let rsp_distance = sift3(
                                    &main_response_body.to_string(),
                                    &response_body.to_string(),
                                );

                                // Check if the `content_length` is greater than 0 and the `distance` is greater than 0.5
                                if content_length > 0
                                    && rsp_distance >= validation_level
                                    && status_code == "200"
                                {
                                    // Print the domain, IP address, status code, and content length
                                    println!(
                                        "**** VIRTUAL HOST DISCOVERED {} -- {} [{}] [{}] RSP Diff = [{}] ****",
                                        dns_domain,
                                        ip_str.to_string(),
                                        status_code,
                                        content_length.to_string(),
                                        rsp_distance.to_string()
                                    );

                                    // Create a JobResult struct with the domain, IP address, and output directory
                                    let job_result = JobResult {
                                        domain: dns_domain.to_string(),
                                        ip: ip_str.to_string(),
                                        outdir: out.to_owned(),
                                    };

                                    // Send the JobResult through the transmitting end of the channel
                                    if let Err(_) = tx.send(job_result).await {
                                        // If there's an error sending the JobResult, continue to the next iteration of the loop
                                        continue;
                                    }
                                } else {
                                    // Print the domain, IP address, status code, and content length
                                    eprintln!(
                                        "[-] {} -- {} RSP Diff = [{}]",
                                        dns_domain,
                                        ip_str.to_string(),
                                        rsp_distance
                                    );
                                    // If the response body is empty, continue to the next iteration of the loop
                                    continue;
                                }
                            } else {
                                let mut unresolved_host = String::from("");
                                // Lookup the IP addresses associated with a name.
                                // The final dot forces this to be an FQDN, otherwise the search rules as specified
                                // in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
                                if let Err(_) =
                                    resolver.lookup_ip(job_host.as_str().to_string()).await
                                {
                                    // If the DNS lookup fails, return early
                                    // The above code is written in the Rust programming language. However, it seems to
                                    // be incomplete or incorrect as it only contains the phrase "unresolved_host"
                                    // followed by three hash symbols. It is not clear what the intended purpose or
                                    // functionality of this code is.
                                    unresolved_host.push_str(&dns_domain);
                                }

                                let main_page = ip_str.clone();
                                let main_site = main_page.clone();

                                // Parse the job IP address into a URL
                                let ip_url = match reqwest::Url::parse(&ip_str.to_string()) {
                                    // If parsing succeeds, assign the parsed URL to 'ip_url'
                                    Ok(u) => u,
                                    // If parsing fails, continue to the next iteration of the loop
                                    Err(_) => {
                                        continue;
                                    }
                                };
                                // Build a request with the GET method and the parsed URL
                                let mut request = Request::new(Method::GET, ip_url);
                                // If false, insert a 'HOST' header with the value 'unresolved_domain' into the request headers
                                // The 'unresolved_domain' variable is assumed to be defined elsewhere in the code
                                // This is to ensure that the request is sent to the specified domain
                                request.headers_mut().insert(
                                    reqwest::header::HOST,
                                    HeaderValue::from_str(&unresolved_host).unwrap(),
                                );

                                // Create a clone of the `request` object and assign it to `request_clone`
                                let request_clone = match request.try_clone() {
                                    // If the `try_clone()` method returns `Some`, which means the cloning was successful,
                                    // assign the cloned object to `rc`
                                    Some(rc) => rc,
                                    // If the `try_clone()` method returns `None`, which means the cloning failed,
                                    // skip to the next iteration of the loop
                                    None => continue,
                                };

                                // Check if a Web Application Firewall (WAF) is detected for the specified host with port
                                if waf::detect_waf(main_site, request_clone).await {
                                    // If a WAF is detected, skip to the next iteration of the loop
                                    continue;
                                }

                                // Make a request with the modified headers using the 'client' object
                                let response = match client.execute(request).await {
                                    // If the request is successful, assign the response to 'response'
                                    Ok(r) => r,
                                    // If there's an error, continue to the next iteration of the loop
                                    Err(_) => continue,
                                };
                                let content_length = match response.content_length() {
                                    // Check if the response has a content length
                                    Some(cl) => cl,
                                    // If the response doesn't have a content length, skip to the next iteration
                                    None => continue,
                                };

                                let status_code = response.status().as_u16().to_string();

                                let response_body = match response.text().await {
                                    // Build the GET request
                                    Ok(r) => r,
                                    // If there's an error building the request, skip to the next iteration
                                    Err(_) => continue,
                                };

                                // Create a new GET request to the main_page
                                let get = client.get(main_page);

                                let req = match get.build() {
                                    // Build the GET request
                                    Ok(r) => r,
                                    // If there's an error building the request, skip to the next iteration
                                    Err(_) => continue,
                                };

                                // Execute the GET request
                                let response2 = match client.execute(req).await {
                                    // If the request is successful, store the response
                                    Ok(r) => r,
                                    // If there's an error executing the request, skip to the next iteration
                                    Err(_) => continue,
                                };

                                let main_response_body = match response2.text().await {
                                    // Build the GET request
                                    Ok(r) => r,
                                    // If there's an error building the request, skip to the next iteration
                                    Err(_) => continue,
                                };

                                // Calculate the SIFT3 distance between the string representations of `main_content_length` and `content_length`
                                let rsp_distance = sift3(
                                    &main_response_body.to_string(),
                                    &response_body.to_string(),
                                );

                                // Check if the `content_length` is greater than 0 and the `distance` is greater than 0.5
                                if content_length > 0
                                    && rsp_distance >= validation_level
                                    && status_code == "200"
                                {
                                    // Print the domain, IP address, status code, and content length
                                    println!(
                                        "**** VIRTUAL HOST DISCOVERED {} -- {} [{}] [{}] RSP Diff = [{}] ****",
                                        dns_domain,
                                        ip_str.to_string(),
                                        status_code,
                                        content_length.to_string(),
                                        rsp_distance.to_string()
                                    );

                                    // Create a JobResult struct with the domain, IP address, and output directory
                                    let job_result = JobResult {
                                        domain: dns_domain.to_string(),
                                        ip: ip_str.to_string(),
                                        outdir: out.to_owned(),
                                    };
                                    // Send the JobResult through the transmitting end of the channel
                                    if let Err(_) = tx.send(job_result).await {
                                        // If there's an error sending the JobResult, continue to the next iteration of the loop
                                        continue;
                                    }
                                } else {
                                    // Print the domain, IP address, status code, and content length
                                    eprintln!(
                                        "[-] {} -- {} RSP Diff = [{}]",
                                        dns_domain,
                                        ip_str.to_string(),
                                        rsp_distance
                                    );
                                    // If the response body is empty, continue to the next iteration of the loop
                                    continue;
                                }
                            }
                        } else {
                            // If the `vhost` flag is not set to true
                            if !host_with_port.is_empty() {
                                // Print the `host_with_port` value
                                println!("{}", host_with_port);
                            }
                        }
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
    } else if port_str == "443" {
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
    } else {
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
