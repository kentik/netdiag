use std::time::Duration;
use anyhow::{anyhow, Result};
use futures::{pin_mut, stream::StreamExt};
use gumdrop::Options;
use tokio::net::lookup_host;
use tokio::time::sleep;
use netdiag::{Bind, Knock, Knocker};

#[derive(Debug, Options)]
pub struct Args {
    #[options()]                help:   bool,
    #[options(default = "4")]   count:  usize,
    #[options(default = "500")] delay:  u64,
    #[options(default = "250")] expiry: u64,
    #[options(free, required)]  host:   String,
    #[options(free, required)]  port:   u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse_args_default_or_exit();
    let Args { count, delay, expiry, host, port, .. } = args;

    let delay  = Duration::from_millis(delay);
    let expiry = Duration::from_millis(expiry);

    let addr = format!("{}:{}", host, port);
    let addr = lookup_host(&addr).await?.next().ok_or_else(|| {
        anyhow!("invalid target")
    })?.ip();

    println!("knocking {} ({})", host, addr);

    let knocker = Knocker::new(&Bind::default()).await?;
    let knock   = Knock { addr, port, count, expiry };
    let stream  = knocker.knock(&knock).await?.enumerate();
    pin_mut!(stream);

    while let Some((n, item)) = stream.next().await {
        match item? {
            Some(d) => println!("seq {} RTT {:0.2?} ", n, d),
            None    => println!("seq {} timeout", n),
        }
        sleep(delay).await;
    }

    Ok(())
}
