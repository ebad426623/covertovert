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
    def send(self, log_file_name, delay, receiverIP):
        """
        
        --- First, we will explain our approach. We selected the covert channel: 
            Covert Storage Channel that exploits Protocol Field Manipulation 
            using RCODE Flag field in DNS [Code: CSC-PSV-DNS-RCF]
            
        - This means that we have 4 bits available in RCODE to encode our data for each packet we send.
        
        - In the question, it states that we can only send 1 or 2 bits of data per packet,
            so we decided to send 2 bits to make it more efficient.
        
        - We could encode 2 bits of data using 4 bits of RCODE, so we decided to use the XOR function.
            The first two bits of RCODE can be used to encode the first bit we need to send,
            and the last two bits of RCODE can be used to encode the second bit we need to send.
        
        - So, if the bit we want to send is 0, it means the two bits of RCODE used to encode it
            should, when XOR'ed, give 0 as output, so both 00 and 11 can be used to encode the bit 0.
        
        - Similarly, if the bit we want to send is 1, it means the two bits of RCODE used to encode it
            should, when XOR'ed, give 1 as output, so both 01 and 10 can be used to encode the bit 1.
        
        - This method allows us to encode the data in a confusing way to anyone who does not know the
            consensus between sender and receiver. This is a good encoding method for the covert operation.
        
        - Additionally, being able to use two different codes for the same bit (for example 01 and 10 for
            bit 1) increases the complexity of the encoding and makes it more difficult to decode it.
            
            
            
            
        --- Now, we will explain the sending code here.
        
        - Firstly, we were getting a syntax warning because of the usage of "iface" in CovertChannelBase.py's 
            send function, so we filtered out the warning to make the output look prettier.
            
        - For the implementation, we first get the message to send covertly as a binary string from
            CovertChannelBase.py's generate random message function.
        
        - We define the encoding of 0s and 1s "bisIsZero" and "bisIsOne". This is just defining the
            truth table for XOR, so it doesn't need to be taken in as a parameter to the "send" function.
        
        - After that, we loop over each bit in the message we want to send. In the loop, we select a random
            encoding for the bit, for example if the bit we want to send is 0, we choose 00 or 11 as the
            encoding randomly.
        
        - We do this encoding for the second bit as well, and concatenate both encodings as a 4-bit binary number.
        
        - We then create a DNS packet, with qr set to 1. This indicates that the message is a response. 
            We use this since in normal DNS communication, the RCODE field is used only in a response
            message, not a query (qr = 0) message. Using query messages with RCODE would arouse suspicion,
            so we decided to use response message so our covert channel is more "covert".
        
        - Lastly, we embed our encoded RCODE into the DNS packet and send it. After sending each packet,
            we wait for a very short time before sending another packet as to not overwhelm the receiver.
            In our testing, if we sent each packet without waiting, the receiver was not able to receive
            all the sent packets and dropped some, this resulted in incomplete transmission of data.
            
        
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
                
            packet = IP(dst = receiverIP)/UDP()/DNS(
            qr = 1, # Seting to 1 for response to avoid detection
            rcode = int(rcode, 2)   # Embedding 2 bits of data here
            )
            
            super().send(packet)
            time.sleep(delay)





    def receive(self, senderIP, log_file_name):
        """
        
        --- We selected the covert channel: 
            Covert Storage Channel that exploits Protocol Field Manipulation 
            using RCODE Flag field in DNS [Code: CSC-PSV-DNS-RCF]
            
            
            
        --- We have explained the approach we took to encode the data in the sending function above,
            so we will explain the receiving function's code here
        
            
        - First, we define some state variables, their uses can be seen from the comments next to them.
        
        - Basically, we are looping over scapy's "sniff" function, until we encounter a "."
            in the received transmission, which indicates end of message.
        
        - In the sniff function, we are filtering incoming packets by udp and port number 53,
            as we are sending packets through udp in the sender, and DNS uses port 53 for communication.
        
        - Additionally, we are sniffing one packet at a time, as we do not know when we will receive 
            "." end of communication, so we cant sniff more than one packet at a time.
        
        - When we receive a packet through sniffing, the "handle_packet" function is called. This
            function basically decodes the RCODE in the incoming DNS packet. I will explain in detail:
        
        - First, we check if the incoming packet is from the sender's IP address. If it is not,
            we discard the packet.
        
        - Additionally, we check if the packet has the DNS layer, if not, we discard it. This check
            is redundant, since the sender code above only sends DNS packets, but we checked just for
            robustness.
        
        - Then, we extract the RCODE from the packet. It will be in the form of decimal integer,
            in the range 0 to 15.
        
        - We convert the integer RCODE into a 4-bit binary string, for example 7 will 
            be converted into "0111".
        
        - The two leftmost bits will correspond to the first received encoded bit, and the two
            rightmost bits will correspond to the second received encoded bit. In the example above
            of "0111", "01" is encoded form of first bit and "11" is encoded form of second bit.
            
        - We decode both bits by using XOR operation on their encoding. For the example above,
            we will XOR "0" and "1" to get 1 as our first decoded bit. Similarly, We will XOR "1" and "1"
            to get 0 as our second decoded bit.
        
        - We will append these decoded bits to the "bits" variable, that stores the previous bits we
            have received. When this variable has size 8, it means it is storing 8 total bits, we
            can decode the bits stored in it into an ASCII character, and append that character into
            the final message string we have received uptil now. We will also clear the "bits" variable
            to store the next incoming character.
        
        - If the character we received is a ".", it means that communication has ended, so we can set
            "receiving" variable to False, so we can stop sniffing.
            
        - In the end, we log the received decoded message.
        
        
        """
        
        
        # defining state variables
        message = ""    # final encoded messaged that is received
        receiving = True    # true until we receive "." indicating end of message
        bits = ""   # string of bits received, when length is 8 it will be turned into char and cleared
        
        
        
        # callback to handle received packet
        def handle_packet(packet):
            
            # importing the above defined state variables
            nonlocal message
            nonlocal receiving
            nonlocal bits
            
            
            
            # if source is anything but the sender, ignore it
            if packet[IP].src != senderIP:
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