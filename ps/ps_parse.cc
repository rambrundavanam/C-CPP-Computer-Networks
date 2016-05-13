
#include <string>
#include <vector>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <getopt.h>

#include "ps_parse.h"

using namespace std;


static int help;
/*
 Prints out the help screen
*/
void help_options(){
  cout<<"=================HELP SCREEN=========================\n";
  cout<<"•--help \n";
  cout<<"\t Example: “./portScanner --help”\n\n";
  cout<<"•--ports <ports to scan> \n";
  cout<<"\t Example: “./portScanner --ports 1,2,3-5”\n\n";
  cout<<"•--ip <IP address to scan>\n";
  cout<<"\t Example: “./portScanner --ip 127.0.0.1”\n\n";
  cout<<"•--prefix <IP prefix to scan>\n";
  cout<<"\t Example: “./portScanner --prefix 127.143.151.123/24”\n\n";
  cout<<"•--file <file name containing IP addresses to scan>\n";
  cout<<"\t Example: “./portScanner --file filename.txt”\n\n";
  cout<<"•--speedup <parallel threads to use>\n";
  cout<<"\t Example: “./portScanner --speedup 10”\n\n";
  cout<<"•--scan <one or more scans>\n";
  cout<<"\t Example: “./portScanner --scan SYN NULL FIN XMAS”\n\n";
  cout<<"=====================================================\n";
  exit(1);
}

/*
 Parses the command-line arguments using getopt
*/
void parse_arguments(int argc, char** argv, psargs_t *psargs){
  int option;
  while (1)
    {
      static struct option long_options[] =
        {
          {"ports",       required_argument,           0, 'a'},
          {"ip",          required_argument,           0, 'b'},
          {"prefix",      required_argument,           0, 'c'},
          {"file",        required_argument,           0, 'd'},
          {"speedup",     required_argument,           0, 'e'},
          {"scan",        required_argument,           0, 'f'},
          {"help",        no_argument,        &help,   0},
          {0, 0, 0, 0}
        };

      int option_index = 0;
      option = getopt_long(argc, argv, "a:b:c:d:e:f:g",long_options, &option_index);

      if (option == -1)
        break;
      switch (option)
        {
        case 0:
          if (long_options[option_index].flag != 0)
          {
            if(argc>2){
              cout<<"\nHelp Cannot be followed by arguments.Check the help options\n";
              exit(0);
            }
            else{
              help_options();
              break;
            }
          }     
        case 'a':
          psargs->ports = optarg;
          break;

        case 'b':
          psargs->ip = optarg;
          break;

        case 'c':
          psargs->prefix = optarg;
          break;

        case 'd':
          psargs->file = optarg;
          break;

        case 'e':
            
            if(atoi(optarg) == 0){              
              psargs->num_of_threads=1;//should be atleast 1
              cout<<"Number of Threads to be created to speed up should be at least 1\n";
              break;
            }
            else{
              psargs->num_of_threads = atoi(optarg);
              break;
            }

        case 'f':
          psargs->scan_types.push_back(optarg);
          for(int i = optind; i < argc; i++) psargs->scan_types.push_back(argv[i]);
          break;
        
        case '?':
          break;

        default:
          exit(0);
        }
    }
}

/*
 Parses the range ports if given a range, saves them to structure
*/
void parse_range_ports(string range_port, int hyphen_pos, vector<int> *all_ports){
  vector<int>& my_ports = *all_ports;
  string second_number = range_port.substr(hyphen_pos+1);
  string first_number = range_port.substr(0,hyphen_pos);
  int sec_num = atoi(second_number.c_str());
  int first_num = atoi(first_number.c_str());
  if(first_num > sec_num){
    cout<<"Invalid port range given\n";
    return;
  }
  else for(int i= first_num; i<(sec_num+1);i++) my_ports.push_back(i);

}

/*
 Parses the comma ports, if given a range, call the range parser
 otherwise saves them to structure
*/
void parse_comma_ports(string port_msg, vector<int> *all_ports){
  vector<int>& my_ports = *all_ports;
  int curr_pos = 0;
  int temp_pos = 0;
  int hyphen_pos = 0;
  string port_to_save, last_port;
  while(curr_pos != port_msg.size()){
    //Check for special case: the last port option
    if(port_msg.find(",",curr_pos) == string::npos){
      last_port = port_msg.substr(curr_pos);
      hyphen_pos = last_port.find("-");
      if(hyphen_pos != string::npos) 
        parse_range_ports(last_port, hyphen_pos, all_ports);
      else my_ports.push_back(atoi(last_port.c_str()));
      curr_pos = port_msg.size();
    }
    //Otherwise, keep getting everything till the next comma
    else{
      curr_pos = port_msg.find(",",temp_pos);
      curr_pos++;
      port_to_save = port_msg.substr(temp_pos,curr_pos-temp_pos-1);
      hyphen_pos = port_to_save.find("-");
      if(hyphen_pos != string::npos) 
        parse_range_ports(port_to_save, hyphen_pos, all_ports);
      else my_ports.push_back(atoi(port_to_save.c_str()));
    }
    temp_pos = curr_pos;
  }
}

/*
 Parses the scan types and saves them to structure
*/
void parse_scan_types(vector<string> args, vector<string> *all_types){
  vector<string>& my_types = *all_types;
  for(int i=0; i < args.size(); i++){
    //If it's a valid scan type, add it, otherwise ignore
    if(args[i] == "SYN" || args[i] == "NULL" || args[i] == "XMAS" || args[i] == "ACK" || args[i] == "FIN" || args[i] == "UDP")
      my_types.push_back(args[i]);
  }
}

