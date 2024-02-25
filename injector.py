import frida
import sys
import argparse

jscodeFile = open("sniffer.js", "r")
jscode = jscodeFile.read()
jscodeFile.close()

def on_message(message, data):
  if message['type'] == 'send':
    print(message['payload'])
  else:
    print(message)

if __name__ == '__main__':
    # Argument Parsing
    parser = argparse.ArgumentParser(description="Frida script runner for network interception.")
    parser.add_argument("app_id", help="The package name (app ID) of the target Android application.") 
    args = parser.parse_args()

    device = frida.get_usb_device()

    process = device.attach(args.app_id)  # Use the argument
    script = process.create_script(jscode)
    script.on('message', on_message)

    print('[+] Running')
    script.load()
    sys.stdin.read()
