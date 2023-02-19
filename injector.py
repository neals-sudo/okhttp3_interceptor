import frida, sys

jscodeFile = open("sniffer.js", "r")
jscode = jscodeFile.read()
jscodeFile.close()

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    else:
        print(message)

device = frida.get_usb_device()

# insert app id here
process = device.attach("com.example.app")
script = process.create_script(jscode)
script.on('message', on_message)

print('[+] Running')
script.load()
sys.stdin.read()
