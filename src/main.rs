// Import the necessary libraries
use async_std::net::TcpStream; // Provides functionality for TCP networking
use clap::{App, Arg}; // Command-line argument parsing library
use futures::{stream::FuturesUnordered, StreamExt}; // Asynchronous programming library
use governor::{Quota, RateLimiter}; // Rate limiting library
use std::{error::Error, net::SocketAddr, time::Duration}; // Standard library modules for error handling, networking, and time
use tokio::{
    // Asynchronous runtime for Rust
    io::{self, AsyncBufReadExt}, // I/O operations and extension traits
    runtime::Builder,            // Builder for creating custom Tokio runtimes
    task,                        // Task handling
};

// Import the `config` module from the `hickory_resolver` crate
use hickory_resolver::config::*;

// Import the `AsyncResolver` struct from the `hickory_resolver` crate
use hickory_resolver::AsyncResolver;

// Import the `TokioAsyncResolver` struct from the `hickory_resolver` crate
use hickory_resolver::TokioAsyncResolver;

// Define a struct called Job
struct Job {
    // The host field is an optional String that represents the host of the job
    host: Option<String>,
    // The ports field is an optional String that represents the ports of the job
    ports: Option<String>,
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

    // Parse the ports argument or use a default value
    let ports = match matches.value_of("ports") {
        Some(ports) => ports.to_string(),
        None => "80,443".to_string(),
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

    // Create a multi-threaded runtime
    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(w)
        .build()
        .unwrap();

    // Spawn a worker thread to send URLs to resolver
    rt.spawn(async move { send_url(job_tx, ports, input_hosts, rate).await });

    // Create a resolver
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Create a collection of worker tasks
    let workers = FuturesUnordered::new();

    // Create worker tasks for resolving DNS

    for _ in 0..concurrency {
        let dns_resolver = resolver.clone();
        let jrx = job_rx.clone();
        workers.push(task::spawn(async move {
            //  run the detector
            run_resolver(jrx, dns_resolver).await
        }));
    }
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
    rx: spmc::Receiver<Job>,
    resolver: AsyncResolver<
        hickory_resolver::name_server::GenericConnector<
            hickory_resolver::name_server::TokioRuntimeProvider,
        >,
    >,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    while let Ok(job) = rx.recv() {
        let job_host: String = job.host.unwrap();
        let job_ports = job.ports.unwrap();

        // send the jobs
        let ports = job_ports.clone();
        let mut resolved_domains: Vec<String> = vec![String::from("")];

        // probe for open ports and perform dns resolution
        let ports_array = ports.split(",");
        for (_, port) in ports_array.enumerate() {
            let job_host_http = job_host.clone().to_string();
            let job_host_https = job_host_http.clone().to_string();
            let http_port = port.to_string();
            let https_port = http_port.to_string();

            // Lookup the IP addresses associated with a name.
            // The final dot forces this to be an FQDN, otherwise the search rules as specified
            //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
            let response = match resolver
                .lookup_ip(job_host_https.as_str().to_string())
                .await
            {
                Ok(r) => r,
                Err(_) => {
                    continue;
                }
            };

            if port == "80" {
                // There can be many addresses associated with the name,
                //  this can return IPv4 and/or IPv6 addresses
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
                            let http_with_port = String::from(format!(
                                "{}{}:{}",
                                "http://", job_host_http, http_port
                            ));
                            resolved_domains.push(http_with_port);
                        }
                        _ => {
                            continue;
                        }
                    }
                }
            } else if port == "443" {
                // There can be many addresses associated with the name,
                //  this can return IPv4 and/or IPv6 addresses
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
                            let https_with_port = String::from(format!(
                                "{}{}:{}",
                                "https://", job_host_https, https_port
                            ));
                            resolved_domains.push(https_with_port);
                        }
                        _ => {
                            continue;
                        }
                    }
                }
            } else {
                // There can be many addresses associated with the name,
                //  this can return IPv4 and/or IPv6 addresses
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
                            let https_with_port = String::from(format!(
                                "{}{}:{}",
                                "https://", job_host_https, https_port
                            ));
                            resolved_domains.push(https_with_port);
                        }
                        _ => {
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
                            let http_with_port = String::from(format!(
                                "{}{}:{}",
                                "http://", job_host_http, http_port
                            ));
                            resolved_domains.push(http_with_port);
                        }
                        _ => {
                            continue;
                        }
                    }
                }
            }
        }

        // Iterate over the resolved domains and print them to stdout.
        for domain in &resolved_domains {
            if domain != "" {
                println!("{}", domain);
            }
        }
    }

    Ok(())
}
