use rfm9x::RFM95;
use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::block_cipher_trait::BlockCipher;
use aes_soft::Aes128;
use std::error::Error;

#[derive(Clone, Copy)]
enum Direction {
	Up = 0x00,
}

// See LoRAWAN specification 4.2.1 "Message type (MType bit field)"
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum MACMessageType {
	JoinRequest = 0b000,
	JoinAccept = 0b001,
	UnconfirmedDataUp = 0b010,
	UnconfirmedDataDown = 0b011,
	ConfirmedDataUp = 0b100,
	ConfirmedDataDown = 0b101,
	RejoinRequest = 0b110,
	Proprietary = 0b111,
}

// See LoRaWAN specification 5 "MAC commands" (line 839)
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum MACCommandUplink {
	ResetInd = 0x01,
	LinkCheckReq = 0x02,
	LinkADRAns = 0x03,
	DutyCycleAnd = 0x04,
	RXParamSetupAns = 0x05,
	DevStatusAns = 0x06,
	NewChannelAns = 0x07,
	RXTimingSetupAns = 0x08,
	TxParamSetupAns = 0x09,
	DlChannelAns = 0x0A,
	RekeyInd = 0x0B,
	ADRParamSetupAns = 0x0C,
	DeviceTimeReq = 0x0D,
	RejoinParamSetupAns = 0x0F
}

// See LoRaWAN specification 5 "MAC commands" (line 839)
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum MACCommandDownlink {
	ResetConf = 0x01,
	LinkCheckAns = 0x02,
	LinkADRReq = 0x03,
	DutyCycleReq = 0x04,
	RXParamSetupReq = 0x05,
	DevStatusReq = 0x06,
	NewChannelReq = 0x07,
	RXTimingSetupReq = 0x08,
	TxParamSetupReq = 0x09,
	DlChannelReq = 0x0A,
	RekeyConf = 0x0B,
	ADRParamSetupReq = 0x0C,
	DeviceTimeAns = 0x0D,
	ForceRejoinReq = 0x0E,
	RejoinParamSetupReq = 0x0F
}

bitflags! {
	struct MACFrameControl: u8 {
		const DEFAULT = 0b0000_0000;
		const ADR = 0b1000_0000;
		const ADR_ACQ_REQ = 0b0100_0000;
		const ACK = 0b0010_0000;
		const FPENDING = 0b0001_0000; // Only valid in uplink
		const FRAME_OPTIONS_LENGTH_MASK = 0b0000_1111;
	}
}

pub struct LoRAWAN<'a> {
	device: &'a mut RFM95,
	device_address: [u8; 4],
	application_session_key: [u8; 16],
	network_session_key: [u8; 16],
	frame_counter: u16,
}

impl<'a> LoRAWAN<'a> {
	pub fn new(
		device: &'a mut RFM95,
		device_address: &[u8; 4],
		app_skey: &[u8; 16],
		network_skey: &[u8; 16],
	) -> LoRAWAN<'a> {
		let mut l: LoRAWAN<'a> = LoRAWAN {
			device: device,
			device_address: [0u8; 4],
			frame_counter: 0,
			application_session_key: [0u8; 16],
			network_session_key: [0u8; 16],
		};
		l.device_address.copy_from_slice(device_address);
		l.application_session_key.copy_from_slice(app_skey);
		l.network_session_key.copy_from_slice(network_skey);
		l
	}

	fn shift_left(data: &mut [u8]) {
		for i in 0..data.len() {
			if i < (data.len() - 1) {
				let overflow = if (data[i + 1] & 0x80) == 0x80 { 1 } else { 0 };
				data[i] = (data[i] << 1) + overflow;
			} else {
				data[i] = data[i] << 1;
			}
		}
	}

	fn xor(a: &mut [u8], b: &[u8]) {
		for i in 0..a.len() {
			a[i] = a[i] ^ b[i];
		}
	}

	fn generate_keys(&self) -> ([u8; 16], [u8; 16]) {
		// Generate initial K1 by encrypting a zero block with the network session key
		let mut k1 = LoRAWAN::aes_encrypt(&[0u8; 16], &self.network_session_key);

		// Check if MSB is 1
		let msb_key = (k1[0] & 0x80) == 0x80;
		LoRAWAN::shift_left(&mut k1);

		if msb_key {
			k1[15] = k1[15] ^ 0x87;
		}

		// Copy K1 to K2
		let mut k2 = k1.clone();

		// Check if MSB is 1
		let msb_k2 = (k2[0] & 0x80) == 0x80;
		LoRAWAN::shift_left(&mut k2);
		if msb_k2 {
			k2[15] = k2[15] ^ 0x87;
		}

		(k1, k2)
	}

	fn calculate_mic(&self, data: &[u8], direction: Direction) -> [u8; 4] {
		let incomplete_block_size = data.len() % 16;
		let number_of_blocks = data.len() / 16 + if incomplete_block_size > 0 { 1 } else { 0 };

		let block_b: [u8; 16] = [
			0x49,
			0x00,
			0x00,
			0x00,
			0x00,
			(direction as u8),
			self.device_address[3],
			self.device_address[2],
			self.device_address[1],
			self.device_address[0],
			(self.frame_counter & 0xFF) as u8,
			((self.frame_counter >> 8) & 0xFF) as u8,
			0x00, // Frame counter upper bytes
			0x00,
			0x00,
			(data.len() as u8),
		];

		let (k1, k2) = self.generate_keys();

		let encrypted_block_b = LoRAWAN::aes_encrypt(&block_b, &self.network_session_key);
		let mut old_data = encrypted_block_b.clone();

		for block_counter in 0..(number_of_blocks - 1) {
			let start = block_counter * 16;
			let mut block_data = [0u8; 16];
			block_data.copy_from_slice(&data[start..(start + 16)]);
			LoRAWAN::xor(&mut block_data, &old_data);

			let encrypted_block = LoRAWAN::aes_encrypt(&block_data, &self.network_session_key);
			old_data = encrypted_block.clone();
		}

		// Perform AES encryption on last block
		let start = (number_of_blocks - 1) * 16;
		let encrypted_last_block = if incomplete_block_size == 0 {
			// Copy last data into array
			let mut block_data = [0u8; 16];
			block_data.copy_from_slice(&data[start..(start + 16)]);
			LoRAWAN::xor(&mut block_data, &k1);
			LoRAWAN::xor(&mut block_data, &old_data);
			LoRAWAN::aes_encrypt(&block_data, &self.network_session_key)
		} else {
			let mut last_block = [0u8; 16];
			for i in 0..16 {
				if i < incomplete_block_size {
					last_block[i] = data[start + i];
				} else if i == incomplete_block_size {
					last_block[i] = 0x80;
				} else {
					last_block[i] = 0x00;
				}
			}

			LoRAWAN::xor(&mut last_block, &k2);
			LoRAWAN::xor(&mut last_block, &old_data);
			LoRAWAN::aes_encrypt(&last_block, &self.network_session_key)
		};

		// MIC is the first four bytes of the encrypted last block
		[
			encrypted_last_block[0],
			encrypted_last_block[1],
			encrypted_last_block[2],
			encrypted_last_block[3],
		]
	}

	fn aes_encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
		let key = GenericArray::from_slice(key);
		let cipher = Aes128::new(&key);
		let mut encrypted_array = GenericArray::clone_from_slice(block);
		cipher.encrypt_block(&mut encrypted_array);
		let mut encrypted = [0u8; 16];
		encrypted.copy_from_slice(&encrypted_array[..]);
		encrypted
	}

	fn encrypt_payload(&self, payload: &[u8], direction: Direction) -> Vec<u8> {
		let incomplete_block_size = payload.len() % 16;
		let number_of_blocks = payload.len() / 16 + if incomplete_block_size > 0 { 1 } else { 0 };
		let mut encrypted_payload = vec![0; payload.len()];

		println!(
			"encrypt_payload {:?} (len={}) num_blocks={} incomplete_block_size={}",
			payload,
			payload.len(),
			number_of_blocks,
			incomplete_block_size
		);

		for i in 1..=number_of_blocks {
			let block_a: [u8; 16] = [
				0x01,
				0x00,
				0x00,
				0x00,
				0x00,
				(direction as u8),
				self.device_address[3],
				self.device_address[2],
				self.device_address[1],
				self.device_address[0],
				(self.frame_counter & 0xFF) as u8,
				((self.frame_counter >> 8) & 0xFF) as u8,
				0x00, // Frame counter upper bytes
				0x00,
				0x00,
				i as u8,
			];

			let encrypted_block_a = LoRAWAN::aes_encrypt(&block_a, &self.application_session_key);

			//Check for last block
			let start = (i - 1) * 16;
			if i != number_of_blocks {
				// XOR data with encrypted block_a
				for j in 0..16 {
					encrypted_payload[start + j] = payload[start + j] ^ encrypted_block_a[j];
				}
			} else {
				let last_size = if incomplete_block_size == 0 {
					16
				} else {
					incomplete_block_size
				};

				for j in 0..last_size {
					encrypted_payload[start + j] = payload[start + j] ^ encrypted_block_a[j];
				}
			}
		}

		encrypted_payload.to_vec()
	}

	fn encrypt_mac_command(&self, mac_command: &[u8], direction: Direction) -> Vec<u8> {
		let mut encrypted_payload = vec![0; mac_command.len()];

		println!("encrypt MAC command {:?} len {}", mac_command, mac_command.len());

		// See 4.3.1.6 Frame options
		let block_a: [u8; 16] = [
			0x01,
			0x00, 0x00, 0x00, 0x00,
			(direction as u8),
			self.device_address[3],
			self.device_address[2],
			self.device_address[1],
			self.device_address[0],
			// TODO: Frame counter should be frame count down for downlink messages? (NFCntDwn)
			(self.frame_counter & 0xFF) as u8,
			((self.frame_counter >> 8) & 0xFF) as u8,
			0x00, 0x00, // Frame counter upper bytes (we only do 16 bits)
			0x00,
			0x00
		];

		let encrypted_block_a = LoRAWAN::aes_encrypt(&block_a, &self.network_session_key);

		for i in 0..mac_command.len() {
			encrypted_payload[i] = mac_command[i] ^ encrypted_block_a[i]
		}

		encrypted_payload.to_vec()
	}

	/** LoRaWAN frame format:
	 *  PHY payload:	| MHDR:8 | MAC payload | MIC: 32 |
	 *  MAC payload:	| FHDR: 56..176 | FPort: 8 | FRMPayload (encrypted) |
	 *  FHDR: 			| DevAddr: 32 | Frame control: 8 | Frame counter: 16 | frame options: 0..120 |
	 *  MHDR:			| MType: 3 | RFU: 3 | Major: 2 |
	 *  Frame control:
	 *  - Uplink:		| ADR: 1 | AdrAckReq: 1 | ACK: 1 | FPending: 1 | FOptsLen: 4 |
	 *  - Downlink:		| ADR: 1 | AdrAckReq: 1 | ACK: 1 | RFU: 1 | FOptsLen: 4 |
	 * Frame options:	| MACCommand_1 8...40 .... MacCommand_n: 8...40 |
	 * MAC command:		| CID: 8 | Args 0..32 |
	 */
	pub fn send_frame(&mut self, payload: &[u8], frame_port: u8) -> Result<(), Box<dyn Error>> {
		let encrypted_payload = self.encrypt_payload(&payload, Direction::Up);
		let frame_control = MACFrameControl::DEFAULT;
		let mac_header = (MACMessageType::UnconfirmedDataUp as u8) << 5; // 0x40: nconfirmed data up

		let mac_commands: Vec<Vec<u8>> = vec![
			vec![MACCommandUplink::ResetInd as u8, 0x01] // Argument is LoRaWAN version number; see line 889 in spec
		];
		let mut encrypted_frame_opts: Vec<u8> = vec![];
		for mac_command in mac_commands {
			// Encrypt MAC command
			let mut encrypted_mac_command = self.encrypt_mac_command(&mac_command, Direction::Up);
			encrypted_frame_opts.append(&mut encrypted_mac_command);
		}

		// Construct packet header
		let frame_header: Vec<u8> = vec![
			mac_header,
			self.device_address[3],
			self.device_address[2],
			self.device_address[1],
			self.device_address[0],
			(frame_control.bits | (encrypted_frame_opts.len() as u8 & MACFrameControl::FRAME_OPTIONS_LENGTH_MASK.bits)),
			(self.frame_counter & 0xFF) as u8,
			((self.frame_counter >> 8) & 0xFF) as u8,
			// frame_opts follow
		];

		let mac_payload_start: Vec<u8> = [&frame_header[..], &encrypted_frame_opts[..], &[frame_port]].concat();

		let packet_so_far = [&mac_payload_start[..], &encrypted_payload[..]].concat();
		let mic = self.calculate_mic(&packet_so_far, Direction::Up);

		// Construct packet
		let phy_payload = [&mac_payload_start[..], &encrypted_payload[..], &mic[..]].concat();
		println!("payload: {:?}", payload);
		println!("encrypted payload: {:?}", encrypted_payload);
		println!("packet: {:?}", phy_payload);

		self.device.send_packet(&phy_payload, true)?;
		self.frame_counter += 1;
		Ok(())
	}
}
