extern crate clap;

pub fn parse_args() -> clap::ArgMatches<'static> {
    let matches = clap::App::new("NFORM - Be nform'd of nmap scans")
        .version("0.1.0")
        .author("Ryan Plyler <g.r.plyler@gmail.com>")
        .about("Detects nmap stealth scans and notifies via Discord Bot")
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
            .help("Discord Bot Auth token (or set DISCORD_TOKEN env var"))
        .arg(clap::Arg::with_name("channel")
            .short("c")
            .long("channel")
            .takes_value(true)
            .help("Discord Bot channel ID (or set DISCORD_CHANNEL_ID env var)" ))
        .arg(clap::Arg::with_name("wait")
            .short("w")
            .long("wait")
            .takes_value(true)
            .help("Delay in seconds between discord notifications"))
        .get_matches();

    matches
}








