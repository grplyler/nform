use pcap::Device;
use std::collections::HashMap;
use std::time::Instant;
use std::env;
use std::process;
use clap::ArgMatches;

mod utils;

static mut CONFIG: Option<Config> = None;

struct Config {
    threshold: u32,
    wait: u32,
    use_discord: bool,
    discord_channel_id: String,
    discord_token: String
}

impl Config {
    fn parse(matches: &ArgMatches) -> Result<Config, &'static str> {

        let mut use_discord = false;

        let discord_channel_id = match matches.value_of("channel") {
            Some(channel) => {
                use_discord = true;
                channel.to_string()
            },
            None => match env::var("DISCORD_CHANNEL_ID") {
                Ok(channel) => {
                    use_discord = true;
                    channel.to_string()
                },
                Err(_) => {
                    use_discord = false;
                    String::from("")
                }
            }
        };

        let discord_token = match matches.value_of("token") {
            Some(value) => {
                use_discord = true;
                value.to_string()
            },
            None => match env::var("DISCORD_TOKEN") {
                Ok(value) => {
                    use_discord = true;
                    value.to_string()
                },
                Err(_) => {
                    use_discord = false;
                    String::from("")
                }
            }        
        };

        // Instantiate Offender HitCounter with Threshold of 10 packets.
        let threshold: u32 = matches.value_of("threshold").unwrap_or("5").parse()
            .expect("threshold must be an integer");

        let wait: u32 = matches.value_of("wait").unwrap_or("10").parse()
            .expect("wait must be an integer");


        Ok(Config {
            threshold,
            wait,
            use_discord,
            discord_channel_id,
            discord_token,
        })
    }
}

struct DecodedPacket {
    hex: String,
    src: String,
    dst: String,
    flag: String,
}

impl DecodedPacket {
    fn from_data(data: &[u8]) -> DecodedPacket {
        DecodedPacket {
            hex: hex::encode(data),
            src: format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]),
            dst: format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]),
            flag: match data[47] {
                0 => String::from("NULL"),
                1 => String::from("FIN"),
                2 => String::from("SYN"),
                4 => String::from("RST"),
                8 => String::from("PSH"),
                16 => String::from("ACK"),
                32 => String::from("URG"),
                _ => String::from("UNKNOWN")
            }
        }
    }
}

struct HitCounter {
    threshold: u32,
    wait: u32,
    map: HashMap<String, u32>,
    notify_times: HashMap<String, Instant>
}

impl HitCounter {
    fn new(threshold: u32, wait: u32) -> HitCounter {
        HitCounter {
            threshold,
            wait,
            map: HashMap::new(),
            notify_times: HashMap::new()
        }
    }

    fn inc(&mut self, ip: &String, packet: &DecodedPacket) {
        
        *self.map.entry(ip.to_string()).or_insert(1) += 1;

        if let Some(count) = self.map.get(&ip.to_string()) {


            if count > &self.threshold {

                // if last discord message sent was 30 seconds ago, send discord notification
                match self.notify_times.get(&ip.to_string()) {
                    Some(&instant) => {

                        // Check that instant was greater than 10 seconds ago
                        let seconds_since = instant.elapsed().as_secs();

                        if seconds_since >= 10 {
                            // Notify with discord
                            println!("{} is potentially scanning us with an nmap {} scan! (Continued Contact)", ip, packet.flag);

                            notify_discord(&packet);

                            // Reset Instant
                            self.notify_times.insert(ip.to_string(), Instant::now()).unwrap();
                        } 

                    }   
                    _ => {

                        // Log to Console first contact
                        println!("{} is potentially scanning us with an nmap {} scan! (First Contact)", ip, packet.flag);

                        // Send first disord notification
                        notify_discord(&packet);

                        // Save time of notification
                        self.notify_times.insert(ip.to_string(), Instant::now());
                    }
                }

            }
        }
    }
}

fn notify_discord(intruder: &DecodedPacket) {

    // Check that We have DISCORD_TOKEN and DISCORD_CHANNELID set

    match env::var("DISCORD_TOKEN") {
        Ok(token) => {
            let mut embed = HashMap::new();
            let mut content = HashMap::new();
        
            content.insert("title", "Scanning Activity");
            let message = format!("`{}` is potentially scanning us with an nmap `{}` scan!", intruder.src, intruder.flag);
            let message = message.to_string();
        
            content.insert("description", &message);
        
            embed.insert("embed", content);
        
        
            let client = reqwest::blocking::Client::new();
            match env::var("DISCORD_CHANNEL_ID") {
                Ok(channel_id) => {
                    let url = format!("https://discord.com/api/v6/channels/{}/messages", channel_id);

                    match client.post(&url)
                        .header("Authorization", format!("Bot {}", token))
                        .json(&embed)
                        .send() {
                            Ok(_) => {},
                            Err(e) => println!("Error sending discord message: {}", e)
                        }
                }
                _ => {}
            }

        }
        _ => {}
    }


}

fn main() {

    // Parse Config with Clap
    let matches = utils::parse_args();
   
    // Parse Config
    // CONFIG = Some(Config::parse(&matches).unwrap());
    let config = Config::parse(&matches).unwrap();

    // Instantiate Capture Device
    let mut cap = Device::lookup().unwrap()
        .open().unwrap();

    // Display Config
    println!("===== Config ===========================================");
    println!("Threshold: {} (Only triggers after this many packets)", config.threshold);
    println!("     Wait: {} (Waits this many seconds before sending another Discord Message)", config.wait);
    if config.use_discord {
        println!("   Notify: Discord");
    } else {
        println!("   Notify: None (set DISCORD_TOKEN and DISCORD_CHANNEL_ID env var to notify with Discord bot)");
    }
    println!("=========================================================");

    // Instantiate Hit Counter
    let mut counter = HitCounter::new(config.threshold, config.wait);
    
    //Apply filter for NMAP
    cap.filter("tcp[tcpflags] == tcp-syn || tcp[tcpflags] == tcp-ack || tcp[tcpflags] == tcp-fin || tcp[tcpflags] == 0 && tcp[14:2] == 1024").unwrap();

    // Listen for packets that match this filter
    println!("Listening for nmap scans...");
    while let Ok(raw_packet) = cap.next() {

        // Decode only crucial information like src, dst, and tcp flags
        let packet = DecodedPacket::from_data(raw_packet.data);

        // Increment the threshold counter for this offending IP
        counter.inc(&packet.src, &packet);

    }
}


