// Import the necessary libraries
use async_std::net::TcpStream; // Provides functionality for TCP networking
use clap::{App, Arg}; // Command-line argument parsing library
use futures::{stream::FuturesUnordered, StreamExt}; // Asynchronous programming library
use governor::{Quota, RateLimiter}; // Rate limiting library
use reqwest::{header::HeaderValue, redirect, Method, Request}; // HTTP client library
use std::{error::Error, net::SocketAddr, process::exit, time::Duration}; // Standard library modules for error handling, networking, and time
use tokio::{
    fs::OpenOptions,                            // File system manipulation
    io::{self, AsyncBufReadExt, AsyncWriteExt}, // Asynchronous I/O operations and extension traits
    runtime::Builder,                           // Builder for creating custom Tokio runtimes
    sync::mpsc,                                 // Asynchronous message passing
    task,                                       // Task handling
};

// Import the `config` module from the `hickory_resolver` crate
use hickory_resolver::config::*;

// Import the `AsyncResolver` struct from the `hickory_resolver` crate
use hickory_resolver::AsyncResolver;

// Import the `TokioAsyncResolver` struct from the `hickory_resolver` crate
use hickory_resolver::TokioAsyncResolver;

// Define a struct called Job
#[derive(Clone, Debug)]
struct Job {
    // The host field is an optional String that represents the host of the job
    host: Option<String>,
    // The ports field is an optional String that represents the ports of the job
    ports: Option<String>,
}

// This code block defines a Rust struct named `JobResult` with the following properties:
#[derive(Clone, Debug)]
pub struct JobResult {
    // `domain`: A public field of type `String`, which holds the domain associated with the job result.
    pub domain: String,
    // `ip`: A public field of type `String`, which holds the IP address associated with the job result.
    pub ip: String,
    // `outdir`: A public field of type `String`, which holds the output directory associated with the job result.
    pub outdir: String,
}

// This is the entry point of the program.
// The #[tokio::main] attribute macro is used to define the main function as an asynchronous function.
#[tokio::main]
async fn main() -> std::io::Result<()> {
    // The main function is async, which means it can perform asynchronous operations.
    // It returns a Result object that represents the success or failure of the program.
    // Parse command line arguments
    let matches = App::new("dnsresolver")
        .version("0.1.0")
        .author("zoidsec <krypt0mux@gmail.com>")
        .about("a very fast dns resolver")
        .arg(
            Arg::with_name("ports")
                .short("p")
                .long("ports")
                .default_value("80,443")
                .takes_value(true)
                .display_order(0)
                .help("The ports to to be used for dns resolution"),
        )
        .arg(
            Arg::with_name("rate")
                .short("r")
                .long("rate")
                .default_value("1000")
                .takes_value(true)
                .display_order(1)
                .help("The rate limit in requests per second"),
        )
        .arg(
            Arg::with_name("concurrency")
                .short("c")
                .long("concurrency")
                .default_value("1000")
                .takes_value(true)
                .display_order(2)
                .help("the number of concurrent hosts to resolve"),
        )
        .arg(
            Arg::with_name("workers")
                .short("w")
                .long("workers")
                .default_value("1")
                .takes_value(true)
                .display_order(3)
                .help("the number of concurrent workers"),
        )
        .arg(
            Arg::with_name("vhost")
                .long("vhost")
                .default_value("false")
                .display_order(4)
                .help("checks if the host is a vhost and prints out the domains associated to the IP address"),
        )
        .arg(
            Arg::with_name("dir")
                .short("d")
                .long("dir")
                .takes_value(true)
                .default_value("vhosts")
                .display_order(4)
                .help("the output directory to store all your virtual hosts that have been enumerated"),
        )
        .get_matches();

    // Parse the rate argument and set a default value if parsing fails
    let rate = match matches.value_of("rate").unwrap().parse::<u32>() {
        Ok(rate) => rate,
        Err(_) => {
            eprintln!("{}", "could not parse rate, using default of 1000");
            100
        }
    };

    // Parse the concurrency argument and set a default value if parsing fails
    let concurrency = match matches.value_of("concurrency").unwrap().parse::<i32>() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("{}", "could not parse concurrency, using default of 1000");
            100
        }
    };

    // Parse the workers argument and set a default value if parsing fails
    let w: usize = match matches.value_of("workers").unwrap().parse::<usize>() {
        Ok(w) => w,
        Err(_) => {
            eprintln!("{}", "could not parse workers, using default of 1");
            1
        }
    };

    // The above code is checking if the "vhost" flag is present in the "matches" object. If the flag
    // is present, the variable "vhost" will be set to true.
    let vhost = matches.is_present("vhost");
    if vhost {
        // Attempt to create a directory named "vhosts" and all its parent directories if they don't exist
        match std::fs::create_dir_all("vhosts") {
            // If the directory creation is successful, store the result in the `m` variable
            Ok(m) => m,
            // If there is an error during directory creation, print the error message to the standard error output
            // and exit the program with a status code of 1
            Err(err) => {
                eprintln!("{}", err);
                exit(1)
            }
        };
    }

    // Parse the ports argument or use a default value
    let ports = match matches.value_of("ports") {
        Some(ports) => ports.to_string(),
        None => "80,443".to_string(),
    };

    // Get the value of the "dir" command line argument using the `matches` object.
    // If a value is provided, assign it to the `outdir` variable as a string.
    // If no value is provided, assign the string "." to the `outdir` variable.
    let outdir = match matches.value_of("dir") {
        Some(outdir) => outdir.to_string(),
        None => "vhost".to_string(),
    };

    // Read input hosts from stdin
    let mut input_hosts = vec![];
    let stdin = io::stdin();
    let reader = io::BufReader::new(stdin);
    let mut lines_stream = reader.lines();
    while let Ok(Some(line)) = lines_stream.next_line().await {
        input_hosts.push(line);
    }

    // Create channels for sending jobs
    let (job_tx, job_rx) = spmc::channel::<Job>();
    let (result_tx, result_rx) = mpsc::channel::<JobResult>(w);

    // Create a multi-threaded runtime
    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(w)
        .build()
        .unwrap();

    // Spawn a worker thread to send URLs to resolver
    rt.spawn(async move { send_url(job_tx, ports, input_hosts, rate).await });

    rt.spawn(async move { write_to_file(result_rx).await });

    // Create a resolver
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Create a collection of worker tasks
    let workers = FuturesUnordered::new();

    // Create worker tasks for resolving DNS
    for _ in 0..concurrency {
        let dns_resolver = resolver.clone();
        let jrx = job_rx.clone();
        let jtx = result_tx.clone();
        let out = outdir.clone();
        workers.push(task::spawn(async move {
            //  run the detector
            run_resolver(jtx, jrx, dns_resolver, vhost, out.as_str()).await
        }));
    }

    // Collect the results from the workers asynchronously and store them in a vector
    let _: Vec<_> = workers.collect().await;

    rt.shutdown_background();
    Ok(())
}

// Define an asynchronous function named `send_url`. It takes in the following parameters:
// - `tx`, a `spmc::Sender<Job>` which is a sender for a single-producer, multi-consumer channel.
// - `ports`, a `String` representing a list of ports.
// - `lines`, a `Vec<String>` representing a list of lines.
// - `rate`, a `u32` representing the rate limit.
async fn send_url(
    mut tx: spmc::Sender<Job>,
    ports: String,
    lines: Vec<String>,
    rate: u32,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // Create a rate limiter with the given rate limit.
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // Iterate over each line in the `lines` vector.
    for line in lines {
        // Create a `Job` struct with the `host` field set to the current line
        // and the `ports` field set to the given `ports` string.
        let msg = Job {
            host: Some(line.to_string().clone()),
            ports: Some(ports.to_string()),
        };

        // Send the `Job` struct through the `tx` sender.
        // If the send operation fails, continue to the next iteration.
        if let Err(_) = tx.send(msg) {
            continue;
        }

        // Wait until the rate limiter allows the next job to be sent.
        lim.until_ready().await;
    }

    // Return an empty `Result` indicating success.
    Ok(())
}

// This is an asynchronous function named "run_resolver" which takes two parameters:
// - `rx`, which is a receiver from the `spmc` crate, used for receiving `Job` objects.
// - `resolver`, which is an instance of the `AsyncResolver` struct from the `hickory_resolver` crate.
//   The `AsyncResolver` struct is parameterized with a type representing a generic connector for name servers.
//   In this case, the connector type is `hickory_resolver::name_server::GenericConnector` which is provided by the `hickory_resolver` crate.
//   The `GenericConnector` type is further parameterized with a type representing the runtime provider.
//   In this case, the runtime provider type is `hickory_resolver::name_server::TokioRuntimeProvider` which is also provided by the `hickory_resolver` crate.
//   This means that the `AsyncResolver` instance is using the `GenericConnector` with the `TokioRuntimeProvider` to handle asynchronous operations.

// The function is marked as `async`, which means it can use `await` to suspend execution until an asynchronous operation completes.

// Overall, this function is responsible for running a resolver asynchronously by receiving `Job` objects from the `rx` receiver and using the `resolver` to handle DNS resolution.
async fn run_resolver(
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

        // Split the `ports` string by commas, convert each port to a string,
        // and collect them into a vector of strings (`Vec<String>`).
        // The resulting vector is assigned to the `ports_array` variable.
        let ports_array = ports
            .split(",")
            .map(|port| port.to_string())
            .collect::<Vec<_>>();

        // probe for open ports and perform dns resolution
        for port in ports_array {
            let job_host_http = job_host.clone().to_string();
            let job_host_https = job_host_http.clone().to_string();
            let http_port = port.to_string();
            let https_port = http_port.to_string();

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

            if port == "80" {
                // There can be many addresses associated with the name,
                // this can return IPv4 and/or IPv6 addresses
                let address = match response.iter().next() {
                    Some(a) => a,
                    None => continue,
                };

                if address.is_ipv4() {
                    let timeout = Duration::from_millis(100);
                    let port_int = match http_port.parse::<u16>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let socket_address = SocketAddr::new(address.clone(), port_int);

                    match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
                        Ok(Ok(_)) => {
                            // If the TCP connection is successful, print the HTTP URL with the port
                            let http_with_port = String::from(format!(
                                "{}{}:{}",
                                "http://", job_host_http, http_port
                            ));
                            if !vhost {
                                println!("{}", http_with_port);
                            } else {
                                // The above code is checking if a virtual host (vhost) is enabled. If it is enabled, it
                                let domain = http_with_port.clone();

                                println!("{}", http_with_port);

                                // If the TCP connection is successful, print the HTTP URL with the port
                                let ip = String::from(format!(
                                    "{}{}:{}",
                                    "http://",
                                    address.to_string(),
                                    http_port
                                ));

                                let ip_url = match reqwest::Url::parse(&ip.to_string()) {
                                    Ok(u) => u,
                                    Err(_) => continue,
                                };

                                // Build a request
                                let mut request = Request::new(Method::GET, ip_url);

                                let url = match reqwest::Url::parse(&http_with_port) {
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
                                    println!(
                                        "\n\t{} belongs to -> {}",
                                        domain,
                                        address.to_string()
                                    );
                                    let job = JobResult {
                                        domain: domain,
                                        ip: address.to_string(),
                                        outdir: out.to_owned(),
                                    };

                                    if let Err(_) = tx.send(job).await {
                                        continue;
                                    }
                                }
                            }
                        }
                        _ => {
                            // If the TCP connection fails, return early
                            continue;
                        }
                    }
                }
            } else if port == "443" {
                // There can be many addresses associated with the name,
                // this can return IPv4 and/or IPv6 addresses
                let address = match response.iter().next() {
                    Some(a) => a,
                    None => continue,
                };

                if address.is_ipv4() {
                    let timeout = Duration::from_millis(100);
                    let port_int = match https_port.parse::<u16>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let socket_address = SocketAddr::new(address.clone(), port_int);

                    match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
                        Ok(Ok(_)) => {
                            // If the TCP connection is successful, print the HTTPS URL with the port
                            let https_with_port = String::from(format!(
                                "{}{}:{}",
                                "https://", job_host_https, https_port
                            ));
                            if !vhost {
                                println!("{}", https_with_port);
                            } else {
                                // The above code is checking if a virtual host (vhost) is enabled. If it is enabled, it
                                let domain = https_with_port.clone();

                                println!("{}", https_with_port);

                                // If the TCP connection is successful, print the HTTPS URL with the port
                                let ip: String = String::from(format!(
                                    "{}{}:{}",
                                    "https://",
                                    address.to_string(),
                                    https_port
                                ));

                                let ip_url = match reqwest::Url::parse(&ip.to_string()) {
                                    Ok(u) => u,
                                    Err(_) => continue,
                                };

                                // Build a request
                                let mut request = Request::new(Method::GET, ip_url);

                                let url = match reqwest::Url::parse(&https_with_port) {
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
                                    println!(
                                        "\n\t{} belongs to -> {}",
                                        domain,
                                        address.to_string()
                                    );
                                    let job = JobResult {
                                        domain: domain,
                                        ip: address.to_string(),
                                        outdir: out.to_owned(),
                                    };

                                    if let Err(_) = tx.send(job).await {
                                        continue;
                                    }
                                }
                            }
                        }
                        _ => {
                            // If the TCP connection fails, return early
                            continue;
                        }
                    }
                }
            } else {
                // There can be many addresses associated with the name,
                // this can return IPv4 and/or IPv6 addresses
                let address = match response.iter().next() {
                    Some(a) => a,
                    None => continue,
                };

                if address.is_ipv4() {
                    let timeout = Duration::from_millis(100);
                    let port_int = match https_port.parse::<u16>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let socket_address = SocketAddr::new(address.clone(), port_int);

                    match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
                        Ok(Ok(_)) => {
                            // If the TCP connection is successful, print the HTTPS URL with the port
                            let https_with_port = String::from(format!(
                                "{}{}:{}",
                                "https://", job_host_https, https_port
                            ));
                            if !vhost {
                                println!("{}", https_with_port);
                            } else {
                                // The above code is checking if a virtual host (vhost) is enabled. If it is enabled, it
                                let domain = https_with_port.clone();

                                println!("{}", https_with_port);

                                // If the TCP connection is successful, print the HTTPS URL with the port
                                let ip = String::from(format!(
                                    "{}{}:{}",
                                    "https://",
                                    address.to_string(),
                                    https_port
                                ));

                                let ip_url = match reqwest::Url::parse(&ip.to_string()) {
                                    Ok(u) => u,
                                    Err(_) => continue,
                                };

                                // Build a request
                                let mut request = Request::new(Method::GET, ip_url);

                                let url = match reqwest::Url::parse(&https_with_port) {
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
                                    println!(
                                        "\n\t{} belongs to -> {}",
                                        domain,
                                        address.to_string()
                                    );
                                    let job = JobResult {
                                        domain: domain,
                                        ip: address.to_string(),
                                        outdir: out.to_owned(),
                                    };

                                    if let Err(_) = tx.send(job).await {
                                        continue;
                                    }
                                }
                            }
                        }
                        _ => {
                            // If the TCP connection
                            continue;
                        }
                    }

                    let timeout = Duration::from_millis(100);
                    let port_int = match port.parse::<u16>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let socket_address = SocketAddr::new(address.clone(), port_int);

                    match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
                        Ok(Ok(_)) => {
                            // If the TCP connection is successful, print the HTTP URL with the port
                            let http_with_port = String::from(format!(
                                "{}{}:{}",
                                "http://", job_host_http, http_port
                            ));
                            if !vhost {
                                println!("{}", http_with_port);
                            } else {
                                println!("{}", http_with_port);

                                // The above code is checking if a virtual host (vhost) is enabled. If it is enabled, it
                                let domain = http_with_port.clone();

                                // If the TCP connection is successful, print the HTTP URL with the port
                                let ip = String::from(format!(
                                    "{}{}:{}",
                                    "http://",
                                    address.to_string(),
                                    http_port
                                ));

                                let ip_url = match reqwest::Url::parse(&ip.to_string()) {
                                    Ok(u) => u,
                                    Err(_) => continue,
                                };

                                // Build a request
                                let mut request = Request::new(Method::GET, ip_url);

                                let url = match reqwest::Url::parse(&http_with_port) {
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
                                    println!(
                                        "\n\t{} belongs to -> {}",
                                        domain,
                                        address.to_string()
                                    );
                                    let job = JobResult {
                                        domain: domain,
                                        ip: address.to_string(),
                                        outdir: out.to_owned(),
                                    };

                                    if let Err(_) = tx.send(job).await {
                                        continue;
                                    }
                                }
                            }
                        }
                        _ => {
                            // If the TCP connection
                            continue;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// This function writes the given `vhost` string to the provided `outfile` file asynchronously.
pub async fn write_to_file(mut rx: mpsc::Receiver<JobResult>) {
    // Continuously receive job results from the receiver
    while let Some(job) = rx.recv().await {
        let domain = job.domain;
        let ip = job.ip;
        let outdir = job.outdir;

        // Create the directory (including parent directories) to store the output file.
        // If the directory creation fails, skip to the next iteration of the loop.
        match std::fs::create_dir_all(format!("{}/{}", outdir, ip)) {
            Ok(c) => c, // The directory was successfully created.
            Err(_) => {
                return; // Skip to the next iteration of the loop.
            }
        };

        // Open the output file in append mode.
        // If the file opening fails, print an error message and exit the program with code 1.
        let mut outfile_handle = match OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(format!("{}/{}/vhosts.txt", outdir, ip))
            .await
        {
            Ok(outfile_handle) => outfile_handle, // The file was successfully opened.
            Err(_) => {
                continue; // Skip to the next iteration of the loop.
            }
        };

        // Convert the `vhost` string to bytes and create a mutable copy of it.
        let mut outbuf = domain.as_bytes().to_owned();
        // Append a newline character to the end of the `outbuf` byte buffer.
        outbuf.extend_from_slice(b"\n");
        // Write the content of the `outbuf` byte buffer to the `outfile` file.
        // If an error occurs during the write operation, return early from the function.
        if let Err(_) = outfile_handle.write(&outbuf).await {
            return; // Skip to the next iteration of the loop.
        }
    }
}
