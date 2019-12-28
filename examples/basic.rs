use rppal::spi::{Bus, Mode, SlaveSelect, Spi};
use std::error::Error;
use lora_wan::LoRAWAN;
use rfm9x::{Band, Channel, DataRate, RFM95};
use std::convert::TryInto;

fn main() -> Result<(), Box<dyn Error>> {
	let device_address = hex::decode("1234AB").expect("decoding device_address failed");
	let app_skey = hex::decode("ABABABABABABABABABABABABABABABAB").expect("decoding app_skey failed");
	let network_skey = hex::decode("ABABABABABABABABABABABABABABABAB").expect("decoding network_skey failed");
	assert_eq!(device_address.len(), 4);
	assert_eq!(app_skey.len(), 16);
	assert_eq!(network_skey.len(), 16);

	println!("Device address: {:?}", device_address);
	println!("Network session key: {:?}", network_skey);
	println!("Application session key: {:?}", app_skey);

	let spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, 4_000_000, Mode::Mode0)?;
	let frame_port = 42;

	let mut rfm = RFM95::new(
		spi,
		5, // IRQ pin
		Some(8), // CS pin
		DataRate::SF7_BW125,
		Band::EU863,
		Channel::Ch3,
	)?;
	rfm.reset(25)?;

	let mut wan = LoRAWAN::new(
		&mut rfm,
		&device_address.as_slice().try_into().unwrap(),
		&app_skey.as_slice().try_into().unwrap(),
		&network_skey.as_slice().try_into().unwrap(),
	);

	wan.send_frame("Hello from Rust".as_bytes(), frame_port)?; // Send a LoRAWAN packet
	Ok(())
}
