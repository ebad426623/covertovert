from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, sniff
import warnings
import random
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, parameter1, parameter2):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        
        # Without this, it was giving me a warning because of code in CoverChannelBase.py
        warnings.filterwarnings("ignore", category=SyntaxWarning)


        # The actual message that will be sent through the covert channel
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        # Defining XOR
        bitIsZero = ["00", "11"]
        bitIsOne = ["01", "10"]
        
        
        length = len(binary_message)
        i = 0
        # Looping over the data to send
        while i < length:
            
            ## First processing first bit
            # If first bit to send is 0, rcode's left side two bits, when xor'ed, will equal 0
            if binary_message[i] == '0':
                rcode = random.choice(bitIsZero)
            
            # Else first bit to send is 1, rcode's left side two bits, when xor'ed, will equal 1
            else:
                rcode = random.choice(bitIsOne)
            
            i += 1
            
            ## Now processing second bit
            # If second bit to send is 0, rcode's right side two bits, when xor'ed, will equal 0
            if binary_message[i] == '0':
                rcode += random.choice(bitIsZero)
            
            # Else second bit to send is 1, rcode's right side two bits, when xor'ed, will equal 1
            else:
                rcode += random.choice(bitIsOne)
            
            i += 1
            
            # Now sending the packet
                
            packet = IP(dst = "receiver")/UDP()/DNS(
            qr = 1, # Seting to 1 for response to avoid detection
            rcode = int(rcode, 2)   # Embedding 2 bits of data here
            )
            
            super().send(packet)
            time.sleep(0.01)





    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        
        
        # defining state variables
        message = ""    # final encoded messaged that is received
        receiving = True    # true until we receive all the prelim packets defining the message length
        bits = ""   # string of bits received, when length is 8 it will be turned into char and cleared
        
        
        
        # callback to handle received packet
        def handle_packet(packet):
            
            # importing the above defined state variables
            nonlocal message
            nonlocal receiving
            nonlocal bits
            
            
            
            # if source is anything but the sender, ignore it
            if packet[IP].src != "172.18.0.2":
                return
            
            # if packet doesn't have a DNS layer, ignore it to avoid errors later in the code
            if not packet.haslayer(DNS):
                return
            
            
            # extracting rcode, and converting it into 4-bit binary
            rcode = packet[DNS].rcode
            rcodeBin = ""
            
            
            for _ in range(4):  # finding each bit and 4 bits, so range(4)
                rcodeBin = str(rcode%2) + rcodeBin
                rcode //= 2
            
            
            # extracting bits
            bit1 = int(rcodeBin[0]) ^ int(rcodeBin[1])
            bit2 = int(rcodeBin[2]) ^ int(rcodeBin[3])
            
            bits += str(bit1) + str(bit2)
            
            # if an entire char is created
            if (len(bits) == 8):
                message += self.convert_eight_bits_to_character(bits)
                bits = ""
                
                # if "." is encountered, indicating end of message
                if (message[-1] == '.'):
                    receiving = False


        # looping to receive dns packets, dns has port 53 so using port 53 to filter
        while (receiving):
            sniff(filter="udp port 53", prn=handle_packet, count = 1)
        
        # in the end, log the received message
        self.log_message(message, log_file_name)