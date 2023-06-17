from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import osmosdr
import rtl_sdr
import threading
import queue
import time
import zlib
from fec import fec_encode, fec_decode

# Predefined key and nonce (example only, generate your own complex key and nonce)
key = b'\x81\x9f\xfa\xa2\xe7\x33\xd4\xbe\x4e\x5b\x2d\xcb\x22\x2f\x80\x9e' \
      b'\xd1\x2a\x6d\x87\x98\x6a\x0d\x1b\xe1\xc4\xf8\x91\xe3\xbc\x0a\xcd'
nonce = b'\x75\x3f\x92\xe8\xed\x30\x9f\xfe\xa5\x6e\x0c\x0f'

class my_chacha20_transmitter:
    def __init__(self, identifier):
        self.samp_rate = 2e6
        self.center_freq = 476.4375e6
        self.gain = 20
        self.tx_queue = queue.Queue()
        self.running = True
        self.packet_size = 1024
        self.fec_n = 255  # Reed-Solomon FEC parameters
        self.fec_k = 223
        self.identifier = identifier

        # Create ChaCha20 cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        self.cipher = Cipher(algorithm, mode=None, backend=default_backend())

        # Transmit signal using HackRF One
        self.tx_src = osmosdr.source("hackrf=0")
        self.tx_src.set_sample_rate(self.samp_rate)
        self.tx_src.set_center_freq(self.center_freq)
        self.tx_src.set_gain(self.gain)

    def transmit(self, msg):
        # Convert text to binary
        txt_binary = ''.join(format(ord(c), '08b') for c in msg)
        binary_vector = list(map(int, txt_binary))

        # Encrypt binary data
        encryptor = self.cipher.encryptor()
        encrypted_data = encryptor.update(bytes(binary_vector)) + encryptor.finalize()

        # Add FEC encoding
        fec_encoded_data = fec_encode(encrypted_data, self.fec_n, self.fec_k)

        # Packetize encoded data with headers and CRC-32 checksums
        packets = self.packetize(fec_encoded_data)

        # Put packets into transmit queue
        self.tx_queue.put(packets)

    def start(self):
        # Start the transmit thread
        transmit_thread = threading.Thread(target=self.transmit_thread)
        transmit_thread.daemon = True
        transmit_thread.start()

        # Wait for the transmit thread to finish
        try:
            while True:
                # Prompt the user for a message to transmit
                msg = input("Enter a message to transmit (or 'q' to quit): ")
                if msg.lower() == 'q':
                    self.running = False
                    break

                # Transmit the message
                self.transmit(msg)

                # Sleep to reduce CPU usage
                time.sleep(0.1)

        except KeyboardInterrupt:
            self.running = False
            transmit_thread.join()

    def transmit_thread(self):
        while self.running:
            try:
                packets = self.tx_queue.get(timeout=1)
            except queue.Empty:
                continue

            # Transmit packets
            for packet in packets:
                self.tx_src.open()
                self.tx_src.send(packet)
                self.tx_src.close()


class my_chacha20_receiver:
    def __init__(self, identifier):
        self.samp_rate = 2e6
        self.center_freq = 476.4375e6
        self.gain = 20
        self.running = True
        self.packet_size = 1024
        self.fec_n = 255  # Reed-Solomon FEC parameters
        self.fec_k = 223
        self.identifier = identifier

        # Create ChaCha20 cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        self.cipher = Cipher(algorithm, mode=None, backend=default_backend())

        # Receive signal using RTL-SDR
        self.rx_src = rtl_sdr.RtlSdr()

    def receive(self):
        # Set up the receiver
        self.rx_src.sample_rate = int(self.samp_rate)
        self.rx_src.center_freq = int(self.center_freq)
        self.rx_src.gain = self.gain

        while self.running:
            samples = self.rx_src.read_samples(int(self.samp_rate))

            # Convert samples to packets
            packets = self.convert_to_packets(samples)

            # Validate and process received packets
            for packet in packets:
                if self.validate_packet(packet):
                    # Remove the header
                    packet_data = packet[4:]

                    # Add FEC decoding
                    fec_decoded_data = fec_decode(packet_data, self.fec_n, self.fec_k)

                    # Decrypt received packet
                    decryptor = self.cipher.decryptor()
                    decrypted_data = decryptor.update(fec_decoded_data) + decryptor.finalize()

                    # Convert decrypted data to text
                    decrypted_text = ''.join(chr(byte) for byte in decrypted_data)

                    # Print the identifier and received message
                    print(f"Received from {self.identifier}: {decrypted_text}")

    def convert_to_packets(self, samples):
        # Convert received samples to packets
        # (Assuming a simplified conversion for demonstration purposes)
        return [samples[i:i+self.packet_size] for i in range(0, len(samples), self.packet_size)]

    def validate_packet(self, packet):
        # In this case, packet validation is done by checking if the packet has the expected size
        return len(packet) == self.packet_size

    def start(self):
        # Start the receive thread
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.daemon = True
        receive_thread.start()

        # Wait for the receive thread to finish
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.running = False
            receive_thread.join()


if __name__ == "__main__":
    tx_identifier = "Transmitter 1"
    rx_identifier = "Receiver 1"

    tx_radio = my_chacha20_transmitter(tx_identifier)
    rx_radio = my_chacha20_receiver(rx_identifier)

    tx_thread = threading.Thread(target=tx_radio.start)
    rx_thread = threading.Thread(target=rx_radio.start)

    tx_thread.start()
    rx_thread.start()

    tx_thread.join()
    rx_thread.join()
