# Covert Storage Channel that exploits Protocol Field Manipulation using RCODE Flag field in DNS [Code: CSC-PSV-DNS-RCF]


1) First, we will explain our approach. We selected the covert channel: Covert Storage Channel that exploits Protocol Field Manipulation using RCODE Flag field in DNS [Code: CSC-PSV-DNS-RCF]
            
This means that we have 4 bits available in RCODE to encode our data for each packet we send.
In the question, it states that we can only send 1 or 2 bits of data per packet, so we decided to send 2 bits to make it more efficient.
We could encode 2 bits of data using 4-bits of RCODE, so we decided to use the XOR function. The first two bits of RCODE can be used to encode the first bit we need to send, and the last two bits of RCODE can be used to encode the second bit we need to send.
So, if the bit we want to send is 0, it means the two bits of RCODE used to encode it should, when XOR'ed, give 0 as output, so both 00 and 11 can be used to encode the bit 0.
Similarly, if the bit we want to send is 1, it means the two bits of RCODE used to encode it should, when XOR'ed, give 1 as output, so both 01 and 10 can be used to encode the bit 1.
This method allows us to encode the data in a confusing way to anyone who does not know the consensus between sender and receiver. This is a good encoding method for the covert operation.
Additionally, being able to use two different codes for the same bit (for example 01 and 10 for bit 1) increases the complexity of the encoding and makes it more difficult to decode it.






2) For the code, the detailed explanation for each line of code is present in the MyCovertChannel.py file for both "send" and "receive" functions. Here, I will explain more about the decisions we took and the challenges we faced.

We considered many different functions to encode our message, like even for 0 and odd for 1, or less than 8 for 0 and greater than 8 for 1, etc. But we settled on XOR as it seemed the most complex out of them, and it also allowed us to encode 2 bits in the 4-bit RCODE field.
Additionally, we decided to use UDP over TCP to transport the DNS packet, for its faster speed.
When creating the DNS packet, we let most of the fields be default since we did not need to set them, and by Occam's razor (don't complicate something when keeping it simpler is better), we only set the DNS packet to "response" mode and we set the RCODE field for the actual encoding.
Initially, we did not wait before sending consecutive packets, but from our testing, the receiver did not have enough time to process them, and thus was dropping packets randomly, so we decided to add a very slight delay after sending each packet to give the receiver enough time to process all the sent packets. The delay is taken in as a parameter in the "send" function, and can be increased at the cost of speed if the channel is still dropping packets on your system, but for our system a delay of 10 milliseconds was enough.





3) Conclusion: overall, this assignment was extremely informative as well as fun to code and experiment with. Due to this, I also implemented another covert channel privately using delays between packets to encode information rather than using header fields.