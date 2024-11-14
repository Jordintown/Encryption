import serial
import time

baud_rate = 9600
handshake_message = "LINK-LOGON"
expected_response = "LOGON-CONFIRM"

def connect_to_arduino():
    port = 'COM3'  # Directly specify COM3
    try:
        print(f"Trying to connect to {port}...")
        arduino = serial.Serial(port, baud_rate, timeout=2)
        time.sleep(2)  # Wait for connection to stabilize

        print(f"Sending handshake '{handshake_message}' to {port}")
        arduino.write(f"{handshake_message}\n".encode('utf-8'))
        time.sleep(2)  # Wait for the Arduino to process and respond

        # Check if data is available
        if arduino.in_waiting > 0:
            response = arduino.readline().decode('utf-8').strip()
            print(f"Received response: '{response}'")
            if response == expected_response:
                print(f"Arduino successfully connected on {port}")
                return arduino
            else:
                print(f"Unexpected response: {response}")
        else:
            print("No response from Arduino.")

        arduino.close()
    except (serial.SerialException, OSError) as e:
        print(f"Error connecting to {port}: {e}")
        return None

# Example usage
arduino = connect_to_arduino()
if arduino:
    arduino.write("Connected!\n".encode('utf-8'))  # Example to confirm connection
    arduino.close()
