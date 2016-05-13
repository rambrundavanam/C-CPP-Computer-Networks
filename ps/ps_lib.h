#ifndef _PS_LIB_H
#define _PS_LIB_H

#include <string>
#include <vector>
#include <map>

#include "ps_parse.h"

#define NUM_OF_IPV4_BITS 32
#define MAX_TCP_PACKET_SIZE 65535
#define IPMAXPACKET 65535

using namespace std;

//Taken from http://www.binarytides.com/dns-query-code-in-c-with-winsock/
struct dnshdr
{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct question
{
	unsigned short q_type;
	unsigned short q_class;
};

struct pseudo_header{
	unsigned long source_ip;
	unsigned long dest_ip;
	char reserved;
	char protocol;
	unsigned short length;
};

struct temp_target{
	string IP;
	int port;
	string scan_type;
	int result;
};

//Our Targets structure one struct per IP
struct ps_targets{
	string IP;
	vector<int> ports;
	map<string, int> results;//Mapping each scan type to a result
};

struct ps_source{
	string IP;
	int port;
};

bool valid_IP(string address);
string find_base_addr(string address, int prefix);
void read_ip_addr_file(const char *file_name, vector<string> *ips);
void ip_addrs_from_prefix(const char *ip_addr, vector<string> *ips);

void send_TCP(int socket, struct ps_source source, string destIP, int destPort, string scan_type);
void send_UDP(int socket, struct ps_source source, string destIP, int destPort);
void* thread_send_TCP(void * arg);
void* thread_send_UDP(void * arg);

uint16_t IP_checksum();
uint16_t TCP_checksum();
uint16_t UDP_checksum();

int random_port(int max_number);
vector<string> parse_port_names();

int create_raw_socket(int protocol);

string get_interface_name();
string get_interface_IP(int socket);

void pcap_sniffer(char * interface, struct temp_target * target);
void pcap_parse(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);
void* thread_sniffer(void * arg);

string verify_services(string IP, int port);

void decide_status(vector<struct temp_target> final_tgts, vector<string> scans);
bool target_exists(vector<string> IPs, string IP, vector<int> ports, int port);


#endif
