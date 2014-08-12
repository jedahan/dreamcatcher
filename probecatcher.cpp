/*
* Copyright (c) 2014, Jonathan Dahan
* Copyright (c) 2014, Matias Fontanini
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* * Redistributions of source code must retain the above copyright
*   notice, this list of conditions and the following disclaimer.
* * Redistributions in binary form must reproduce the above
*   copyright notice, this list of conditions and the following disclaimer
*   in the documentation and/or other materials provided with the
*   distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/
// #define DEBUG

#include <iostream>
#include <set>
#include <string>
#include <tins/tins.h>
#include <signal.h>

using namespace Tins;
using namespace std;

class BeaconSniffer {
public:
		void run(const string &iface);
		void printMap(int signum);
private:
		typedef Dot11::address_type address_type;
		typedef map< address_type,set<string> > probe_map;
		probe_map probes;
		bool callback(PDU &pdu);
		char * indexToLabel(int index);
};

void BeaconSniffer::run(const std::string &iface) {
		Sniffer sniffer(iface, Sniffer::PROMISC, "type mgt subtype probe-req", true);
		sniffer.sniff_loop(make_sniffer_handler(this, &BeaconSniffer::callback));
}

char * BeaconSniffer::indexToLabel(int index){
	int length = 1+(index / 26);
	int offset = index % 26;
	char * label = new char[length+1];
	for(int i=0; i<=length; i++){
		label[i] = 97 + offset;
	}
	label[length] = '\0';
	return label;
}

bool BeaconSniffer::callback(PDU &pdu) {
		// Get the Dot11 layer
		const Dot11ProbeRequest &probe = pdu.rfind_pdu<Dot11ProbeRequest>();

		// All probes must have from_ds == to_ds == 0
		if(!probe.from_ds() && !probe.to_ds()) {
				// Get the probe request address
				address_type addr = probe.addr2();
				// Look it up in our graph
				probe_map::iterator it = probes.find(addr);
	string ssid = probe.ssid();
	// TODO: learn what BROADCAST is for in Probe Requests
	if(ssid != "BROADCAST"){
				if(it == probes.end()) {
						// First time we encounter this BSSID.
						try {
								// Create a new mapping if we never saw this before
		set<string> ssids;
		ssids.insert(ssid);
								probes.insert(pair< address_type,set<string> > (addr, ssids) );
								#ifdef DEBUG
		cout << "new prober " << addr << endl;
								#endif
						}
						catch(runtime_error&) {
								// No ssid, just ignore it.
						}
				} else {
		// if this prober exists, add the ssid to the set
		set<string> ssids = it->second;
		set<string>::iterator it = ssids.find(ssid);
		if(it != ssids.end() ){
			ssids.insert(ssid);
		}
	}
	}
		}
		return true;
}

// Prints a dot-style digraph of nodes
void BeaconSniffer::printMap(int signum) {
		#ifdef DEBUG
		printf("Caught signal %d\n",signum);
		#endif
		printf("digraph ssids {\n");
		vector<string> nodes;
		map<int,int> links;

		for (auto& kv : probes) {
				address_type hw_address = kv.first;
	string addr = hw_address.to_string();
	nodes.push_back(hw_address.to_string());
	int from = nodes.size();
	for(string ssid : kv.second){
			if(find(nodes.begin(), nodes.end(), ssid) == nodes.end()){
				nodes.push_back(ssid);
			}
			int to = nodes.size();
			links.insert(pair<int,int> (from, to) );
	}
		}

		int offset = 0;
		for (string node : nodes){
			cout << "\t" << indexToLabel(offset) << " [label=\"" << node << "\"];" << endl;
			offset++;
		}

		for (auto& kv : links) {
			cout << "\t" << indexToLabel(kv.first) << " -> " << indexToLabel(kv.second) << ";" << endl;
		}

		cout << "}" << endl;
}

BeaconSniffer * the_sniffer;

void handleUSR(int signum){
		the_sniffer->printMap(signum);
}

int main(int argc, char* argv[]) {
		// By default, sniff wlan1
		string interface = "wlan1";
		if(argc == 2)
				interface = argv[1];
		BeaconSniffer sniffer;
		the_sniffer = &sniffer;
		// handle SIGUSR1
		signal(SIGUSR1, handleUSR);
		sniffer.run(interface);
}
