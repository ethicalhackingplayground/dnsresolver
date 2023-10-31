mod resolver;
mod waf;
// Import the necessary libraries
use clap::{App, Arg}; // Command-line argument parsing library
use futures::{stream::FuturesUnordered, StreamExt}; // Asynchronous programming library
use governor::{Quota, RateLimiter};
use regex::Regex;
// Rate limiting library
use std::{error::Error, fs::File, io::BufRead, net::IpAddr, process::exit}; // Standard library modules for error handling, networking, and time
use tokio::{
    fs::OpenOptions,                            // File system manipulation
    io::{self, AsyncBufReadExt, AsyncWriteExt}, // Asynchronous I/O operations and extension traits
    runtime::Builder,                           // Builder for creating custom Tokio runtimes
    sync::mpsc,                                 // Asynchronous message passing
    task,                                       // Task handling
};

// Import the `config` module from the `hickory_resolver` crate
use hickory_resolver::config::*;

// Import the `TokioAsyncResolver` struct from the `hickory_resolver` crate
use hickory_resolver::TokioAsyncResolver;

// Define a struct called Job
#[derive(Clone, Debug)]
pub struct Job {
    // The host field is an optional String that represents the host of the job
    pub host: Option<String>,
    // The ports field is an optional String that represents the ports of the job
    pub ports: Option<String>,
    // The unresolved_host field is an optional String that represents the unresolved host of the job
    pub unresolved_host: Option<String>,
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

// Define a function called `banner`
fn banner() {
    // Define a constant variable called `BANNER` that holds a multiline string
    // The `r#` prefix allows the use of raw string literals, which means that escape sequences like `\n` are treated as literal characters instead of special characters
    const BANNER: &str = r#"
         __                                __               
    ____/ /___  _____________  _________  / /   _____  _____
   / __  / __ \/ ___/ ___/ _ \/ ___/ __ \/ / | / / _ \/ ___/
  / /_/ / / / (__  ) /  /  __(__  ) /_/ / /| |/ /  __/ /    
  \__,_/_/ /_/____/_/   \___/____/\____/_/ |___/\___/_/     

                   @z0idsec  v0.1.0                                      
    "#;

    // Print the value of `BANNER` to the standard error stream
    eprintln!("{}", BANNER);
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
                .default_value("")
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
            Arg::with_name("resolvers")
                .long("resolvers")
                .default_value("")
                .takes_value(true)
                .display_order(4)
                .help("the file containing a list of resolvers to use"),
        )
        .arg(
            Arg::with_name("vhost")
                .long("vhost")
                .display_order(5)
                .help("checks if the host is a vhost and prints out the domains associated to the IP address"),
        )
        .arg(
            Arg::with_name("vhost-file")
                .long("vhost-file")
                .default_value("")
                .takes_value(true)
                .display_order(6)
                .help("the file containing a list of unresolved domains or ips to check if they are virtual hosts"),
        )
        .arg(
            Arg::with_name("check-localhost")
                .long("check-localhost")
                .display_order(7)
                .help("check if localhost is a vhost"),
        )
        .arg(
            Arg::with_name("validation-level")
                .long("validation-level")
                .takes_value(true)
                .default_value("1000.0")
                .display_order(8)
                .help("validation threshold, higher means more accuracy"),
        )
        .arg(
            Arg::with_name("dir")
                .short("d")
                .long("dir")
                .takes_value(true)
                .default_value("vhosts")
                .display_order(9)
                .help("the output directory to store all your virtual hosts that have been enumerated"),
        )
        .arg(
            Arg::with_name("show-unresolved")
                .long("show-unresolved")
                .default_value("false")
                .display_order(10)
                .help("this will only print out the unresolved hosts to stdout"),
        )
        .get_matches();

    // Call the `banner` function to display a banner.
    banner();

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
            1000
        }
    };

    // Parse the concurrency argument and set a default value if parsing fails
    let validation_level = match matches.value_of("validation-level").unwrap().parse::<f32>() {
        Ok(c) => c, // If parsing the value as a float succeeds, assign it to `validation_level`
        Err(_) => {
            eprintln!(
                "{}",
                "could not parse validation-level, using default of 1000.0"
            ); // Print an error message if parsing fails
            1000.0 // Assign a default value of 100.0 to `validation_level`
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

    let mut check_localhost = false; // Initialize a variable called `check_localhost` with the value `false`
    if vhost {
        // Check if the `vhost` variable is truthy
        check_localhost = matches.is_present("check-localhost"); // If `vhost` is truthy, assign the result of `matches.is_present("check-localhost")` to `check_localhost`
    }

    // Check if the `vhost` variable is truthy
    let show_unresolved = matches.is_present("show-unresolved"); // If `vhost` is truthy,
                                                                 // assign the result of `matches.is_present("check-localhost")`
                                                                 // to `check_localhost`

    // Check if the command-line argument "vhost-file" has a value
    // If it has a value, assign it to the variable "vhost_files"
    // If it doesn't have a value, assign an empty string to "vhost_files"
    let vhost_path = match matches.value_of("vhost-file") {
        Some(v) => v,
        None => "",
    };

    // Create an empty vector to store the vhost domains
    let mut vhosts_domains = vec![];

    // Read the list of DNS resolvers from a file
    if !vhost_path.is_empty() {
        let vhost_file = match File::open(vhost_path) {
            Ok(f) => f,
            Err(err) => {
                // Print the error message and exit with code 1
                eprintln!("{}", err);
                exit(1)
            }
        };

        // Create a buffered reader to read the file line by line
        let vhost_reader = std::io::BufReader::new(vhost_file);

        // Iterate over each line in the file
        for dns_vhost in vhost_reader.lines() {
            vhosts_domains.push(dns_vhost.unwrap());
        }
    }

    // Parse the ports argument or use a default value
    let ports = match matches.value_of("ports") {
        Some(ports) => ports.to_string(),
        None => "".to_string(),
    };

    // Parse the ports argument or use a default value
    let resolvers = match matches.value_of("resolvers") {
        Some(resolvers) => resolvers.to_string(),
        None => "".to_string(),
    };

    // Get the value of the "dir" command line argument using the `matches` object.
    // If a value is provided, assign it to the `outdir` variable as a string.
    // If no value is provided, assign the string "." to the `outdir` variable.
    let outdir = match matches.value_of("dir") {
        Some(outdir) => outdir.to_string(),
        None => "vhost".to_string(),
    };

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
    rt.spawn(async move { send_url(job_tx, ports, rate, vhosts_domains).await });

    // Spawn a worker thread to write results to a file
    rt.spawn(async move { write_to_file(result_rx).await });

    // Create an empty vector to store resolvers
    let mut resolver_list = vec![];

    let mut resolver_config = ResolverConfig::default();

    // Check if resolvers is not empty
    if !resolvers.is_empty() {
        // Read the list of DNS resolvers from a file
        let file = match File::open(resolvers) {
            Ok(f) => f,
            Err(err) => {
                // Print the error message and exit with code 1
                eprintln!("{}", err);
                exit(1)
            }
        };

        // Create a buffered reader to read the file line by line
        let reader = std::io::BufReader::new(file);

        // Iterate over each line in the file
        for line in reader.lines() {
            let server_address = match line {
                Ok(s) => s,
                Err(err) => {
                    // Print the error message and exit with code 1
                    eprintln!("{}", err);
                    exit(1)
                }
            };

            // Parse the server address string into an IpAddr
            let ip_addr = match server_address.parse::<IpAddr>() {
                Ok(ip_addr) => {
                    // Successfully parsed the IP address string
                    ip_addr
                }
                Err(e) => {
                    // Failed to parse the IP address string
                    eprintln!("Failed to parse the IP address: {}", e);
                    continue;
                }
            };

            // Add the IP address to the resolver list
            resolver_list.push(ip_addr);
        }

        // Create a NameServerConfigGroup from your list of resolvers
        let name_server_group =
            NameServerConfigGroup::from_ips_clear(resolver_list.as_slice(), 53, true);

        // Create a ResolverConfig using from_parts
        resolver_config = ResolverConfig::from_parts(None, vec![], name_server_group);
    }

    // Create a resolver
    let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());

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
            resolver::run_resolver(
                jtx,
                jrx,
                dns_resolver,
                vhost,
                validation_level,
                check_localhost,
                show_unresolved,
                out,
            )
            .await
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
// - `rate`, a `u32` representing the rate limit.
async fn send_url(
    mut tx: spmc::Sender<Job>,
    ports: String,
    rate: u32,
    unresolved: Vec<String>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // Create a rate limiter with the given rate limit.
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // Read input from the standard input
    let stdin = io::stdin();
    let reader = io::BufReader::new(stdin);
    let mut lines_stream = reader.lines();

    // Iterate over each line in the input stream
    while let Ok(Some(line)) = lines_stream.next_line().await {
        if unresolved.len() > 0 {
            for unresolved_domain in &unresolved {
                // Perform wildcard validation using a regular expression
                // The regular expression matches lines that start with "*." followed by a domain name
                // The domain name consists of lowercase letters, a dot, and at least one more character
                let re = match Regex::new(format!("{}", r#"^\*\.([a-z]+\.[a-z].+)$"#).as_str()) {
                    Ok(re) => re,
                    Err(_) => continue,
                };

                // Iterate over each capture group in the regular expression match
                if re.is_match(&line) {
                    for cap in re.captures_iter(&line) {
                        if cap.len() > 0 {
                            // Create a `Job` struct with the `host` field set to the current line
                            // and the `ports` field set to the given `ports` string.
                            let msg = Job {
                                host: Some(cap[1].to_string().clone()),
                                ports: Some(ports.to_string()),
                                unresolved_host: Some(unresolved_domain.to_string()),
                            };

                            // Send the `Job` struct through the `tx` sender.
                            // If the send operation fails, continue to the next iteration.
                            if let Err(_) = tx.send(msg) {
                                continue;
                            }
                            break;
                        }
                    }
                } else {
                    // Create a `Job` struct with the `host` field set to the current line
                    // and the `ports` field set to the given `ports` string.
                    let msg = Job {
                        host: Some(line.to_string().clone()),
                        ports: Some(ports.to_string()),
                        unresolved_host: Some(unresolved_domain.to_string()),
                    };

                    // Send the `Job` struct through the `tx` sender.
                    // If the send operation fails, continue to the next iteration.
                    if let Err(_) = tx.send(msg) {
                        continue;
                    }
                }

                // Wait until the rate limiter allows the next job to be sent.
                lim.until_ready().await;
            }
        } else {
            // Perform wildcard validation using a regular expression
            // The regular expression matches lines that start with "*." followed by a domain name
            // The domain name consists of lowercase letters, a dot, and at least one more character
            let re = match Regex::new(format!("{}", r#"^\*\.([a-z]+\.[a-z].+)$"#).as_str()) {
                Ok(re) => re,
                Err(_) => continue,
            };

            // Iterate over each capture group in the regular expression match
            if re.is_match(&line) {
                for cap in re.captures_iter(&line) {
                    if cap.len() > 0 {
                        // Create a `Job` struct with the `host` field set to the current line
                        // and the `ports` field set to the given `ports` string.
                        let msg = Job {
                            host: Some(cap[1].to_string().clone()),
                            ports: Some(ports.to_string()),
                            unresolved_host: Some("".to_string()),
                        };

                        // Send the `Job` struct through the `tx` sender.
                        // If the send operation fails, continue to the next iteration.
                        if let Err(_) = tx.send(msg) {
                            continue;
                        }
                        break;
                    }
                }
            } else {
                // Create a `Job` struct with the `host` field set to the current line
                // and the `ports` field set to the given `ports` string.
                let msg = Job {
                    host: Some(line.to_string().clone()),
                    ports: Some(ports.to_string()),
                    unresolved_host: Some("".to_string()),
                };

                // Send the `Job` struct through the `tx` sender.
                // If the send operation fails, continue to the next iteration.
                if let Err(_) = tx.send(msg) {
                    continue;
                }
            }

            // Wait until the rate limiter allows the next job to be sent.
            lim.until_ready().await;
        }
    }

    // Return an empty `Result` indicating success.
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
