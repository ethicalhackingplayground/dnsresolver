// use chrono::{Local, Datelike, Timelike};

use async_std::net::TcpStream;
use clap::{App, Arg};
use futures::{stream::FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use std::{error::Error, net::SocketAddr, time::Duration};
use tokio::{
    io::{self, AsyncBufReadExt},
    runtime::Builder,
    task,
};

use hickory_resolver::AsyncResolver;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;

struct Job {
    host: Option<String>,
    ports: Option<String>,
}

/**
 * The main entry point
 */
#[tokio::main]
async fn main() -> std::io::Result<()> {
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

    let rate = match matches.value_of("rate").unwrap().parse::<u32>() {
        Ok(rate) => rate,
        Err(_) => {
            eprintln!("{}", "could not parse rate, using default of 1000");
            100
        }
    };

    let concurrency = match matches.value_of("concurrency").unwrap().parse::<i32>() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("{}", "could not parse concurrency, using default of 1000");
            100
        }
    };

    let w: usize = match matches.value_of("workers").unwrap().parse::<usize>() {
        Ok(w) => w,
        Err(_) => {
            eprintln!("{}", "could not parse workers, using default of 1");
            1
        }
    };

    let ports = match matches.value_of("ports") {
        Some(ports) => ports.to_string(),
        None => "80,443".to_string(),
    };

    let mut input_hosts = vec![];
    let stdin = io::stdin();
    let reader = io::BufReader::new(stdin);
    let mut lines_stream = reader.lines();
    while let Ok(Some(line)) = lines_stream.next_line().await {
        input_hosts.push(line);
    }

    // job channels
    let (job_tx, job_rx) = spmc::channel::<Job>();

    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(w)
        .build()
        .unwrap();

    // Set up a worker pool with the number of threads specified from the arguments
    rt.spawn(async move {
        send_url(job_tx, ports, input_hosts, rate).await
    });

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default());

    // process the jobs
    let workers = FuturesUnordered::new();

    // process the jobs for scanning.
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

/**
 * Sends the job to the workers
 */
async fn send_url(
    mut tx: spmc::Sender<Job>,
    ports: String,
    lines: Vec<String>,
    rate: u32
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    for line in lines {
        let msg = Job {
            host: Some(line.to_string().clone()),
            ports: Some(ports.to_string()),
        };
        if let Err(_) = tx.send(msg) {
            continue;
        }
        // send the jobs
        lim.until_ready().await;
    }
    Ok(())
}

/**
 * This function will be in charge of resolving and probing the hosts
 */
async fn run_resolver(rx: spmc::Receiver<Job>, resolver: AsyncResolver<hickory_resolver::name_server::GenericConnector<hickory_resolver::name_server::TokioRuntimeProvider>>) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
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

        // Iterate over the resolved IP addresses and send HTTP requests
        for domain in &resolved_domains {
            if domain != "" {
                println!("{}", domain);
            }
        }
    }

    Ok(())
}
