use clap::Parser;
use colored::*;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, COOKIE, USER_AGENT},
    Client, Proxy,
};
use serde::{Deserialize, Serialize};
use std::{fs, str::FromStr, sync::Arc, time::{Duration, Instant}};
use tokio::sync::Semaphore;

const COMMON_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

const ALL_METHODS: &[&str] = &[
    "ACL", "ARBITRARY", "BASELINE-CONTROL", "BCOPY", "BDELETE", "BIND",
    "BMOVE", "BPATCH", "BPROPFIND", "BPROPPATCH", "CHECKIN", "CHECKOUT",
    "CONNECT", "COPY", "DELETE", "GET", "GETLIB", "GIBBERISH", "HEAD",
    "INDEX", "LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY", "MKCOL",
    "MKREDIRECTREF", "MKWORKSPACE", "MOVE", "NOTIFY", "OPTIONS", "ORDERPATCH",
    "PATCH", "POLL", "POST", "PROPFIND", "PROPPATCH", "PURGE", "PUT",
    "REBIND", "REPORT", "SEARCH", "SUBSCRIBE", "TRACE", "UNBIND", "UNCHECKOUT",
    "UNLINK", "UNLOCK", "UNSUBSCRIBE", "UPDATE", "UPDATEREDIRECTREF",
    "VERSION-CONTROL", "X-MS-ENUMATTS",
];

const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];


#[derive(Parser, Debug)]
#[command(
    name = "hvt",
    about = "HTTP Verb Tampering - probe HTTP verbs/methods to find bypass & misconfiguration",
    version,
    after_help = "EXAMPLES:\n  hvt -u https://example.com\n  hvt -u https://example.com --all -t 20\n  hvt -u https://example.com -m GET,PURGE,FUZZ --hide 405\n  hvt -u https://api.example.com -H 'Authorization: Bearer tok' -j out.json"
)]
struct Args {
    /// Target URL (must include scheme, e.g., https://example.com/path)
    #[arg(short, long)]
    url: String,

    /// Concurrent threads
    #[arg(short, long, default_value = "5")]
    threads: usize,

    /// Test all known HTTP methods
    #[arg(long, conflicts_with_all = ["safe", "methods", "wordlist"])]
    all: bool,

    /// Test only safe methods: GET, HEAD, OPTIONS
    #[arg(long, conflicts_with_all = ["all", "methods", "wordlist"])]
    safe: bool,

    /// Custom comma-separated methods to test (e.g., GET,POST,FUZZ)
    #[arg(short, long, value_delimiter = ',', conflicts_with_all = ["all", "safe", "wordlist"])]
    methods: Option<Vec<String>>,

    /// Path to a wordlist file (one HTTP method per line, # for comments)
    #[arg(short, long, conflicts_with_all = ["all", "safe", "methods"])]
    wordlist: Option<String>,

    /// Show only results with these status codes (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    show: Option<Vec<u16>>,

    /// Hide results with these status codes (comma-separated)
    #[arg(short = 'x', long, value_delimiter = ',')]
    hide: Option<Vec<u16>>,

    /// Add custom request header, repeatable (format: "Name: Value")
    #[arg(short = 'H', long = "header", action = clap::ArgAction::Append)]
    headers: Option<Vec<String>>,

    /// Cookie string (format: "name=value; name2=value2")
    #[arg(short, long)]
    cookie: Option<String>,

    /// HTTP proxy URL (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080)
    #[arg(long)]
    proxy: Option<String>,

    /// Accept invalid/self-signed TLS certificates
    #[arg(short = 'k', long)]
    insecure: bool,

    /// Follow HTTP redirects (default: disabled to reveal 3xx responses)
    #[arg(short = 'L', long)]
    follow_redirects: bool,

    /// Request timeout in seconds
    #[arg(short = 'T', long, default_value = "10")]
    timeout: u64,

    /// Save text results to file
    #[arg(short, long)]
    output: Option<String>,

    /// Export results as JSON to file
    #[arg(short, long)]
    json: Option<String>,

    /// Suppress banner and informational output
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MethodResult {
    method: String,
    status: u16,
    size: usize,
    time_ms: u128,
    allow_header: Option<String>,
    error: Option<String>,
}

/// Probe a URL with a specific HTTP method and return the result as a MethodResult
async fn probe(client: Arc<Client>, url: String, method: String) -> MethodResult {
    let req_method = match reqwest::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(e) => {
            return MethodResult {
                method,
                status: 0,
                size: 0,
                time_ms: 0,
                allow_header: None,
                error: Some(format!("invalid method: {e}")),
            };
        }
    };

    let start = Instant::now();
    let result = client.request(req_method, &url).send().await;
    let elapsed = start.elapsed().as_millis();

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let allow_header = resp
                .headers()
                .get("allow")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let body = resp.bytes().await.unwrap_or_default();
            MethodResult {
                method,
                status,
                size: body.len(),
                time_ms: elapsed,
                allow_header,
                error: None,
            }
        }
        Err(e) => MethodResult {
            method,
            status: 0,
            size: 0,
            time_ms: elapsed,
            allow_header: None,
            error: Some(e.to_string()),
        },
    }
}

/// Banner
const BANNER: &str = concat!(
    "\n",
    "  HTTP Verb Tampering (hvt)",
    env!("CARGO_PKG_VERSION"),
    " - (c) https://affolter-engineering.ch",
    "\n",
);

/// Return a colored string based on the HTTP status code
fn status_color(status: u16, s: &str) -> ColoredString {
    match status {
        200..=299 => s.green().bold(),
        300..=399 => s.cyan(),
        400..=499 => s.yellow(),
        500..=599 => s.red().bold(),
        _ => s.normal(),
    }
}

/// Return a textual representation of the HTTP status code
fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Print the results in a formatted table
fn print_table(results: &[MethodResult]) {
    let mw = results.iter().map(|r| r.method.len()).max().unwrap_or(6).max(6);
    let sep = "─".repeat(mw + 50);

    println!(
        " {:<mw$}  {:<9}  {:<12}  {:<9}  {}",
        "Method".bold(),
        "Status".bold(),
        "Size".bold(),
        "Time".bold(),
        "Info".bold(),
        mw = mw,
    );
    println!("{}", sep.dimmed());

    for r in results {
        if r.error.is_some() {
            let padded = format!("{:<mw$}", r.method, mw = mw);
            println!(
                " {}  {:<9}  {:<12}  {:<9}  {}",
                padded.dimmed(),
                "ERR".red(),
                "-",
                format!("{}ms", r.time_ms),
                r.error.as_deref().unwrap_or("").red(),
            );
            continue;
        }

        let padded_method = format!("{:<mw$}", r.method, mw = mw);
        let method_col = status_color(r.status, &padded_method);
        let status_col = status_color(r.status, &r.status.to_string());

        let mut info = status_text(r.status).to_string();
        if let Some(ref allow) = r.allow_header {
            if !info.is_empty() {
                info.push_str("  ");
            }
            info.push_str(&format!("Allow: {allow}").dimmed().to_string());
        }

        println!(
            " {}  {:<9}  {:<12}  {:<9}  {}",
            method_col,
            status_col,
            format!("{} B", r.size),
            format!("{} ms", r.time_ms),
            info,
        );
    }
}

/// Print a summary of the scan results
fn print_summary(results: &[MethodResult], target: &str) {
    let total = results.len();
    let errors = results.iter().filter(|r| r.error.is_some()).count();
    let success: Vec<&MethodResult> = results
        .iter()
        .filter(|r| r.error.is_none() && matches!(r.status, 200..=299))
        .collect();

    println!();
    println!("{}", "Summary".bold());
    println!("  Target  : {}", target.cyan());
    println!("  Tested  : {}", total.to_string().bold());
    println!(
        "  Errors  : {}",
        if errors > 0 {
            errors.to_string().red().to_string()
        } else {
            "0".green().to_string()
        }
    );

    if !success.is_empty() {
        let names: Vec<String> = success
            .iter()
            .map(|r| format!("{} [{}]", r.method, r.status))
            .collect();
        println!("  2xx     : {}", names.join(", ").green().bold());
    }

    // Highlight non-GET/HEAD methods that returned 2xx which could likely be interesting
    let interesting: Vec<&MethodResult> = results
        .iter()
        .filter(|r| {
            r.error.is_none()
                && matches!(r.status, 200..=299 | 301 | 302)
                && !matches!(r.method.as_str(), "GET" | "HEAD")
        })
        .collect();

    if !interesting.is_empty() {
        println!();
        let names: Vec<String> = interesting
            .iter()
            .map(|r| format!("{} [{}]", r.method, r.status))
            .collect();
        println!(
            "  {} Potentially interesting: {}",
            "!".yellow().bold(),
            names.join(", ").yellow().bold()
        );
    }
    println!();
}

/// Entry point of the application
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if !args.quiet {
        println!("{}", BANNER.cyan().bold());
    }

    // Resolve method list
    let methods: Vec<String> = if let Some(ref path) = args.wordlist {
        fs::read_to_string(path)?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_uppercase())
            .collect()
    } else if let Some(ref custom) = args.methods {
        custom.iter().map(|m| m.to_uppercase()).collect()
    } else if args.safe {
        SAFE_METHODS.iter().map(|s| s.to_string()).collect()
    } else if args.all {
        ALL_METHODS.iter().map(|s| s.to_string()).collect()
    } else {
        COMMON_METHODS.iter().map(|s| s.to_string()).collect()
    };

    if methods.is_empty() {
        anyhow::bail!("No methods to test.");
    }

    if !args.quiet {
        let mode = if args.all {
            "all".to_string()
        } else if args.safe {
            "safe".to_string()
        } else if args.wordlist.is_some() {
            format!("wordlist ({})", args.wordlist.as_deref().unwrap_or(""))
        } else if args.methods.is_some() {
            "custom".to_string()
        } else {
            "common".to_string()
        };

        println!("  Target   : {}", args.url.cyan());
        println!(
            "  Methods  : {} ({})",
            methods.len().to_string().bold(),
            mode
        );
        println!("  Threads  : {}", args.threads.to_string().bold());
        println!(
            "  TLS      : {}",
            if args.insecure { "skip verify".yellow() } else { "verify".green() }
        );
        println!(
            "  Redirects: {}",
            if args.follow_redirects { "follow".cyan() } else { "off".normal() }
        );
        println!();
    }

    // Build request headers
    let mut header_map = HeaderMap::new();
    header_map.insert(
        USER_AGENT,
        HeaderValue::from_static("hvt/0.1 (security-testing)"),
    );
    if let Some(ref cookie) = args.cookie {
        header_map.insert(COOKIE, HeaderValue::from_str(cookie)?);
    }
    if let Some(ref headers) = args.headers {
        for h in headers {
            match h.split_once(':') {
                Some((name, value)) => {
                    let name = name.trim();
                    let value = value.trim();
                    header_map.insert(HeaderName::from_str(name)?, HeaderValue::from_str(value)?);
                }
                None => eprintln!("{} Skipping malformed header: {h}", "warn:".yellow()),
            }
        }
    }

    // Build HTTP client
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .danger_accept_invalid_certs(args.insecure)
        .default_headers(header_map);

    if !args.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if let Some(ref proxy_url) = args.proxy {
        builder = builder.proxy(Proxy::all(proxy_url)?);
    }

    let client = Arc::new(builder.build()?);
    let semaphore = Arc::new(Semaphore::new(args.threads));

    // Dispatch probes
    let mut handles = Vec::with_capacity(methods.len());
    for method in &methods {
        let client = Arc::clone(&client);
        let sem = Arc::clone(&semaphore);
        let url = args.url.clone();
        let method = method.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            probe(client, url, method).await
        }));
    }

    let mut results: Vec<MethodResult> = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(r) => results.push(r),
            Err(e) => eprintln!("{} task panicked: {e}", "error:".red()),
        }
    }

    // Preserve original method order (as given by the wordlist/arg), stable sort
    let method_order: std::collections::HashMap<&str, usize> = methods
        .iter()
        .enumerate()
        .map(|(i, m)| (m.as_str(), i))
        .collect();
    results.sort_by_key(|r| method_order.get(r.method.as_str()).copied().unwrap_or(usize::MAX));

    // Apply status-code filters
    let filtered: Vec<MethodResult> = results
        .into_iter()
        .filter(|r| {
            if let Some(ref show) = args.show {
                return show.contains(&r.status);
            }
            if let Some(ref hide) = args.hide {
                return !hide.contains(&r.status);
            }
            true
        })
        .collect();

    if !args.quiet {
        print_table(&filtered);
        print_summary(&filtered, &args.url);
    }

    // Persist results
    if let Some(ref path) = args.output {
        let mut text = format!("hvt - {}\n{}\n\n", args.url, "=".repeat(60));
        for r in &filtered {
            if let Some(ref e) = r.error {
                text.push_str(&format!("{:<20} ERROR  {e}\n", r.method));
            } else {
                text.push_str(&format!(
                    "{:<20} {:>5}   {:>10} B   {:>6}ms{}\n",
                    r.method,
                    r.status,
                    r.size,
                    r.time_ms,
                    r.allow_header
                        .as_ref()
                        .map(|a| format!("   Allow: {a}"))
                        .unwrap_or_default()
                ));
            }
        }
        fs::write(path, &text)?;
        if !args.quiet {
            println!("  {} Saved to {path}", "✓".green());
        }
    }

    if let Some(ref path) = args.json {
        let payload = serde_json::json!({
            "target": args.url,
            "method_set": if args.all { "all" } else if args.safe { "safe" } else { "custom" },
            "results": filtered,
        });
        fs::write(path, serde_json::to_string_pretty(&payload)?)?;
        if !args.quiet {
            println!("  {} JSON saved to {path}", "✓".green());
        }
    }

    Ok(())
}
