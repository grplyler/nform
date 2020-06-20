extern crate clap;

pub fn parse_args() -> clap::ArgMatches<'static> {
    let matches = clap::App::new("nform - Be nform'd of nmap scan")
        .version("0.1.0")
        .author("Ryan Plyler <grplyler@liberty.edu>")
        .about("Detects stealth nmap scans and notifies via Discord Bot")
        .arg(clap::Arg::with_name("threshold")
            .short("t")
            .long("threshold")
            .takes_value(true)
            .help("Number of scanning packets to capture before triggered"))
        .arg(clap::Arg::with_name("discord")
            .short("d")
            .long("discord")
            .takes_value(false)
            .help("Use discord bot to notify of scanning activity"))
        .arg(clap::Arg::with_name("token")
            .short("k")
            .long("token")
            .takes_value(true)
            .help("Discord Bot Auth token"))
        .arg(clap::Arg::with_name("channel")
            .short("c")
            .long("channel")
            .takes_value(true)
            .help("Discord Bot channel ID"))
        .arg(clap::Arg::with_name("wait")
            .short("w")
            .long("wait")
            .takes_value(true)
            .help("Delay in seconds between discord notifications"))
        .get_matches();

    matches
}








