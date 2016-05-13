BitTorrent Client
Authors: Abdulrahman Kurdi & Ram Brundavanam
Professor: Dr. Apu Kapadia
Submission Date:Oct 19, 2014

The BitTorrent client is a Peer to Peer file sharing system. The senders of the files are called seeders
and the receivers are called leechers. The peer who wants a particular file, needs to request for the file
on the network based on the torrent file information. The leecher will get the torrent file and opens the
torrent file using the bit torrent client. He then sends a connection request to the seeder.
The seeder will see the connection request and establishes a connection by sending a message called
Bit torrent protocol which contains the message in ben-coded format. This message has the . The seeder
checks for the SHA1 of the file for the file information and establishes the connection.

The seeder and leecher will send handshake messages to each other based on the SHA1 of the torrent
file information. If both of them have the same SHA1 , the handshake is said to be successful. And the
seeder and leecher will proceed further.

Once the handshake is successful, the leecher will set it self to unchoked and sends an unchoked
message to the seeder. The seeder will check the unchoked message and set itself to unchoked to
proceed with sharing the file.

The seeder will then calculate the bitfiled message of the file that he needs to send and will send the
bitfield message to the leecher. Each bit in the bitfield message represents a piece of the file and each
file is divided into blocks. The leecher will calculate his bitfield message and compares it with the
seeders bitfield message. If he is interested in any of the pieces, he will send the interested message.
The seeder will see the interested message and waits for the piece request message. The leecher will
create a piece request message which contains the piece requested, offset, and its length block by block.
The seeder will parse the piece request message and sends the requested piece block by block to the
seeder appropriately. We are able to do till here successfully.

We attempted to read the piece message from the seeder but we were unsuccessful although we wrote
the message successfully to the leecher.

How to run our Program?

The seeder will give the following commands:
make
./bt_client -v -b localhost:6666 download.mp3

The leecher will give the following commands:
make
./bt_client -v -p localhost:6666 download.mp3.torrentBitTorrent Client

We have the following files in the project:
1)bt_setup.cc/h:
Provides a functionality for parsing the command line arguments
2)bt_lib.cc/h:
The main BitTorrent function library with all the BitTorrent related functions and structures for
messages and arguments.
3)bt_client.cc:
This contains the main function of our program which calls all the fuctions of the BitTorrent client
from the library.
4) .torrent file:
This file contains the torrent information and the file information.
5)file:
This is the actual file that is to be sent.
6)makefile:
This compiles and links the project files.
7)Readme:
This file contains the information of our project and description.
