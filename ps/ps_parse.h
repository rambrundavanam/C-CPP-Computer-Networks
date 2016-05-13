#ifndef _PS_PARSE_H
#define _PS_PARSE_H

#include <string>
#include <vector>

using namespace std;

struct psargs_t{
  string ip;
  string prefix;
  string file;
  string ports;
  int num_of_threads;
  vector <string> scan_types;
};


void help_options();
void parse_arguments(int argc, char** argv, psargs_t *psargs);
void parse_range_ports(string range_port, int hyphen_pos, vector<int> *all_ports);
void parse_comma_ports(string port_msg, vector<int> *all_ports);
void parse_scan_types(vector<string> args, vector<string> *all_types);

#endif
