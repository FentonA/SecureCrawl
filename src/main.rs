mod crawler;
mod scanner;
use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about = "SecureCrawl - Security-focused web crawler")]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long, default_value_t = 3)]
    depth: usize,

    #[arg(short, long, default_value_t = 10)]
    concurrency: usize,

    #[arg(short, long, default_value = "result.json")]
    output: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("SecureCrawl Starting...");
    println!("Target: {}", args.url);
    println!("Max Depth: {}", args.depth);
    println!("Concurrency: {}", args.concurrency);

    Ok(())
}
