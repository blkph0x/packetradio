import os
import sys
import tkinter as tk
import queue
import threading
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import rtlsdr
import numpy as np
from math import log
import pkgutil
import traceback
import urllib.request
import shutil
import subprocess
import lzma
import py7zr


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
    def __init__(self, identifier, key, nonce):
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
    def __init__(self, identifier, key, nonce):
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


def install_pip():
    print("Installing pip...")

    # Check if pip is already installed
    if check_pip():
        print("pip is already installed.")
        return

    try:
        # Download get-pip.py
        url = "https://bootstrap.pypa.io/get-pip.py"
        response = urllib.request.urlopen(url)
        data = response.read()

        # Save get-pip.py locally
        script_dir = os.path.dirname(os.path.abspath(__file__))
        get_pip_path = os.path.join(script_dir, "get-pip.py")
        with open(get_pip_path, "wb") as f:
            f.write(data)

        # Run get-pip.py
        subprocess.run([sys.executable, get_pip_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        print("pip installed successfully.")
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)


def check_pip():
    print("Checking for pip...")
    pip_check = subprocess.run([sys.executable, "-m", "pip", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return pip_check.returncode == 0


def install_module(module):
    print(f"Installing module: {module}...")
    subprocess.run([sys.executable, "-m", "pip", "install", module], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def install_required_modules():
    print("Installing required modules...")
    required_modules = [
        "numpy",
        "cryptography",
        "pyrtlsdr"
    ]
    for module in required_modules:
        if not check_module(module):
            install_module(module)


def check_module(module):
    return pkgutil.find_loader(module) is not None


def install_chocolatey():
    print("Installing Chocolatey...")
    subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            r"iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))",
        ],
        shell=True,
    )


def check_chocolatey():
    print("Checking for Chocolatey...")
    choco_check = subprocess.run(["where", "choco"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return choco_check.returncode == 0


def get_choco_executable():
    choco_executable = r"C:\ProgramData\chocolatey\bin\choco.exe"
    return choco_executable


def check_dependency(package, choco_executable):
    check_command = [choco_executable, "list", "--local-only", package]
    check_result = subprocess.run(check_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return check_result.returncode == 0


def install_with_choco(choco_executable, package):
    install_command = [choco_executable, "install", "-y", package]
    subprocess.run(install_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def install_dependencies():
    print("Installing required dependencies...")

    # Check if Chocolatey is available
    if not check_chocolatey():
        install_chocolatey()

    # Get the path to choco.exe
    choco_executable = get_choco_executable()

    # Update Chocolatey environment variable
    os.environ['PATH'] = f"{os.path.dirname(choco_executable)};{os.environ['PATH']}"

    # Install libusb if not found
    if not check_dependency("libusb", choco_executable):
        print("libusb not found. Installing libusb...")
        install_with_choco(choco_executable, "libusb")


def download_and_extract(url, destination):
    filename = url.split("/")[-1]
    file_path = os.path.join(destination, filename)
    print(f"Downloading {filename}...")
    urllib.request.urlretrieve(url, file_path)

    print(f"Extracting {filename}...")
    extracted_dir = os.path.splitext(file_path)[0]
    if os.path.exists(extracted_dir):
        shutil.rmtree(extracted_dir)

    with py7zr.SevenZipFile(file_path, mode="r") as archive:
        archive.extractall(destination)

    print(f"{filename} extracted successfully.")


def install_libusb():
    print("Installing libusb...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    libusb_dir = os.path.join(script_dir, "libusb", "libusb-1.0.24")

    if os.path.exists(libusb_dir):
        shutil.rmtree(libusb_dir)

    try:
        libusb_archive = os.path.join(script_dir, "libusb-1.0.24.7z")
        download_and_extract("https://github.com/libusb/libusb/releases/download/v1.0.24/libusb-1.0.24.7z", script_dir)
        extracted_dir = os.path.join(script_dir, "libusb-1.0.24")
        print(f"Extracted dir: {extracted_dir}")
        os.makedirs(libusb_dir, exist_ok=True)
        for item in os.listdir(extracted_dir):
            item_path = os.path.join(extracted_dir, item)
            shutil.move(item_path, libusb_dir)
        shutil.rmtree(extracted_dir)
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)

    print("libusb installed successfully.")


def download_librtlsdr():
    print("Downloading librtlsdr...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    librtlsdr_dir = os.path.join(script_dir, "librtlsdr")

    if os.path.exists(librtlsdr_dir):
        shutil.rmtree(librtlsdr_dir)

    try:
        subprocess.run(["git", "clone", "https://github.com/librtlsdr/librtlsdr.git", librtlsdr_dir], cwd=script_dir)
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)


def build_librtlsdr():
    print("Building librtlsdr...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    librtlsdr_dir = os.path.join(script_dir, "librtlsdr")
    build_dir = os.path.join(librtlsdr_dir, "build")

    try:
        os.makedirs(build_dir, exist_ok=True)
        subprocess.run(["cmake", "-S", librtlsdr_dir, "-B", build_dir], cwd=script_dir)
        subprocess.run(["cmake", "--build", build_dir], cwd=script_dir)
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)


def main():
    try:
        # Install pip if not available
        if not check_pip():
            install_pip()

        # Install required Python modules
        install_required_modules()

        # Install required dependencies using Chocolatey
        install_dependencies()

        # Install libusb
        install_libusb()

        # Download librtlsdr source code
        download_librtlsdr()

        # Build librtlsdr
        build_librtlsdr()

        # Initialize the transmitter and receiver objects
        key = b'\x00' * 32  # Replace with your own key
        nonce = b'\x00' * 12  # Replace with your own nonce
        transmitter = MyChacha20Transmitter("TX", key, nonce)
        receiver = MyChacha20Receiver("RX", key, nonce)

        # Start the transmitter and receiver threads
        transmitter.start()
        receiver.start()

        # Start the GUI
        gui = RadioTunerGUI(transmitter, receiver)
        gui.run()

    except Exception as e:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
