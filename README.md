
<h1 align="center">
  NFORM
</h1>

<h3 align="center">Detect NMAP stealth scans and notify via discord bot</h3>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#download">Download</a> •
  <a href="#credits">Credits</a> •
  <a href="#related">Related</a> •
  <a href="#license">License</a>
</p>


## Key Features
* **Detect nmap stealth scans**
    * Tested with `SYN`, `FIN`, `AKC`, `XMAS` and others
* **Small, Single Binary**
    * `nmap` tailed packet filtration and detection in a `6.9M` binary.
* **Fast and Memory Efficient**
    * nform uses about 3MB of memory when running and very little CPU with and `nmap -T5` scan
* **Portable**
* **Cross platform**
    * Windows Binary Comming Soon!

## How To Use

**Using nform on Linux (amd64)**

Download the binary

```
wget https://github.com/grplyler/nform/releases/download/v0.1.0/nform
```

Add Execute Permission
```
chmod +x ./nform
```

Run with defaults (uses main interface)
```
./nform
```

Output
```
===== Config ===========================
Threshold: 5 (Only triggers after this many packets)
     Wait: 10 (Waits this many seconds before sending another Discord Message)
   Notify: Discord
========================================
Listening for nmap scans...
```

Options
```
NFORM - Be nform'd of nmap scans 0.1.0
Ryan Plyler <g.r.plyler@gmail.com>
Detects nmap stealth scans and notifies via Discord Bot

USAGE:
    nform [FLAGS] [OPTIONS]

FLAGS:
    -d, --discord    Use discord bot to notify of scanning activity
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --channel <channel>        Discord Bot channel ID (or set DISCORD_CHANNEL_ID env var)
    -t, --threshold <threshold>    Number of scanning packets to capture before triggered
    -k, --token <token>            Discord Bot Auth token (or set DISCORD_TOKEN env var
    -w, --wait <wait>              Delay in seconds between discord notifications
```

## Rationale

I wrote this little tool to accomplish the following goals
* Learn Rust
* Have very simple reconsiiance intrusion detection without having to install something heavier like `snort` or the like.
* Explore Packets and the Layer 2 Level (For my Major in Networking & Security)

## Disclaimer

The code and executables in this project are a **work in progress**. While they can be used an tools/toys and what have you, they are not production ready and **shouldn't be used on crital systems** without understanding these disclaimers. 

Also, as I am very new to the Rust language, I am sure the code is much messier than nessecary, so I welcome constructive critisism and pull requests!

## Contributing

If you like this project, here are some ways you can contribute!

* Feature Requests
* Bug Reports (Although writing in Rust means significantly less bugs)
* Platform Testing

## Credits

This software uses the following open source packages:

- [libpcap](https://nodejs.org/) (For portable packet capture)
- [tcpdump](https://www.tcpdump.org/) (For initial testing)
- [pcap](https://crates.io/crates/pcap) (Rust bindings for libpcap)
- [hex](https://crates.io/crates/hex) (Rust library for hex conversion)
- [reqwest](https://crates.io/crates/reqwest) (Rust library for http requests)
- [clap](https://crates.io/crates/clap) (Expressive Argument Parser for Rust)
- [Carbon](http://carbon.now.sh) (Code Screenshots)


## Support

## License

MIT




