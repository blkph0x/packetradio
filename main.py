import os
import sys
import tkinter as tk
import queue
import threading
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import rtlsdr  # Import the RtlSdr class from the rtlsdr library
import numpy as np
from math import log
librtlsdr_path = "C:\\Users\\Blkph0x\\Desktop\\PacketRadio\\librtlsdr\\"
os.environ['PATH'] = f"{librtlsdr_path};{os.environ['PATH']}"
# Predefined key and nonce (example only, generate your own complex key and nonce)
key = b'\x81\x9f\xfa\xa2\xe7\x33\xd4\xbe\x4e\x5b\x2d\xcb\x22\x2f\x80\x9e' \
      b'\xd1\x2a\x6d\x87\x98\x6a\x0d\x1b\xe1\xc4\xf8\x91\xe3\xbc\x0a\xcd'
nonce = b'\x75\x3f\x92\xe8\xed\x30\x9f\xfe\xa5\x6e\x0c\x0f'

def fec_encode(data, n, k):
    generator_poly = get_generator_poly(n, k)
    padded_data = np.concatenate((data, np.zeros(n - k, dtype=int)))
    remainder = polynomial_division(padded_data, generator_poly)
    return np.concatenate((data, remainder))


def fec_decode(data, n, k):
    syndromes = calculate_syndromes(data, n, k)
    if np.count_nonzero(syndromes) == 0:
        return data[:k]
    error_locator_poly = find_error_locator_polynomial(syndromes)
    error_positions = find_error_positions(error_locator_poly)
    if len(error_positions) > n - k:
        raise ValueError("Too many errors to correct")
    corrected_data = np.copy(data)
    for position in error_positions:
        corrected_data[position] ^= 1
    return corrected_data[:k]


def get_generator_poly(n, k):
    generator = [1]
    for i in range(n - k):
        generator = polynomial_multiplication(generator, [1, galois_field_exp(i)])
    return generator


def calculate_syndromes(data, n, k):
    syndromes = np.zeros(n - k, dtype=int)
    for i in range(n - k):
        syndrome = 0
        for j in range(k):
            syndrome ^= galois_field_mul(data[j], galois_field_exp(i * j))
        syndromes[i] = syndrome
    return syndromes


def find_error_locator_polynomial(syndromes):
    n = len(syndromes) * 2
    m = len(syndromes)
    error_locator = np.zeros(m + 1, dtype=int)
    old_error_locator = np.zeros(m + 1, dtype=int)
    error_locator[0] = 1
    old_error_locator[0] = 1
    for i in range(1, m + 1):
        discrepancy = syndromes[i - 1]
        for j in range(1, i):
            discrepancy ^= galois_field_mul(error_locator[j], syndromes[i - j - 1])
        if discrepancy != 0:
            if i > m // 2:
                error_locator = np.copy(old_error_locator)
                error_locator = np.roll(error_locator, 1)
                error_locator[0] = 1
                for j in range(1, m + 1):
                    error_locator[j] ^= galois_field_mul(old_error_locator[j], discrepancy)
            else:
                error_locator = np.roll(error_locator, 1)
                error_locator[0] = 1
                for j in range(1, m + 1):
                    error_locator[j] ^= galois_field_mul(old_error_locator[j], discrepancy)
            old_error_locator = np.copy(error_locator)
    return error_locator


def find_error_positions(error_locator_poly):
    positions = []
    n = len(error_locator_poly) - 1
    for i in range(1, n + 1):
        if error_locator_poly[i] != 0:
            positions.append(n - i)
    return positions


def polynomial_division(dividend, divisor):
    dividend_len = len(dividend)
    divisor_len = len(divisor)
    quotient = np.zeros(dividend_len, dtype=int)
    temp_dividend = np.copy(dividend)
    for i in range(dividend_len - divisor_len + 1):
        quotient[i] = temp_dividend[i]
        if quotient[i] != 0:
            for j in range(1, divisor_len):
                if divisor[j] != 0:
                    temp_dividend[i + j] ^= galois_field_mul(divisor[j], quotient[i])
    remainder = temp_dividend[-(dividend_len - divisor_len + 1):]
    return remainder


def polynomial_multiplication(poly1, poly2):
    product = np.zeros(len(poly1) + len(poly2) - 1, dtype=int)
    for i in range(len(poly1)):
        for j in range(len(poly2)):
            product[i + j] ^= galois_field_mul(poly1[i], poly2[j])
    return product


def galois_field_exp(power):
    return 2 ** power


def galois_field_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return galois_field_exp((log(a, 2) + log(b, 2)) % 255)


class MyChacha20Transmitter:
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
        self.tx_src = rtlsdr.RtlSdr()

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


class MyChacha20Receiver:
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
        self.rx_src = rtlsdr.RtlSdr()

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
                    print("Received from {}: {}".format(self.identifier, decrypted_text))

    def convert_to_packets(self, samples):
        # Convert received samples to packets
        # (Assuming a simplified conversion for demonstration purposes)
        return [samples[i:i + self.packet_size] for i in range(0, len(samples), self.packet_size)]

    def validate_packet(self, packet):
        # In this case, packet validation is done by checking if the packet has the expected size
        return len(packet) == self.packet_size

    def start(self):
        # Start the receive thread
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.daemon = True
        receive_thread.start()


class RadioTunerGUI:
    def __init__(self, tx_radio, rx_radio):
        self.tx_radio = tx_radio
        self.rx_radio = rx_radio

        # Create the main window
        self.window = tk.Tk()
        self.window.title("Radio Communication System")
        self.window.geometry("400x500")

        # Text Input for Transmission
        self.text_input_label = tk.Label(self.window, text="Enter a message to transmit:")
        self.text_input_label.pack()
        self.text_input = tk.Entry(self.window)
        self.text_input.pack()

        # Transmit Button
        self.transmit_button = tk.Button(self.window, text="Transmit", command=self.transmit_message)
        self.transmit_button.pack()

    def transmit_message(self):
        msg = self.text_input.get()
        self.tx_radio.transmit(msg)

    def run(self):
        # Start the receive thread
        receive_thread = threading.Thread(target=self.rx_radio.start)
        receive_thread.daemon = True
        receive_thread.start()

        # Start the GUI main loop
        self.window.mainloop()


if __name__ == "__main__":
    tx_identifier = "Transmitter 1"
    rx_identifier = "Receiver 1"

    tx_radio = MyChacha20Transmitter(tx_identifier)
    rx_radio = MyChacha20Receiver(rx_identifier)

    gui = RadioTunerGUI(tx_radio, rx_radio)
    gui.run()
