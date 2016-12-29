#include <iostream>
#include <set>
#include <string>
#include <tins/tins.h>
 
using std::set;
using std::cout;
using std::endl;
using std::string;
using std::runtime_error;

using namespace Tins;

HWAddress<6> expected_address("a8:94:f6:cd:6d:46");
//HWAddress<6> expected_address("04:bd:88:62:8f:70");

class BeaconSniffer {
public:
    void run(const string& iface);
private:
    typedef Dot11::address_type address_type;
    typedef set<address_type> ssids_type;
 
    bool callback(PDU& pdu);

    ssids_type ssids;
};
 
void BeaconSniffer::run(const std::string& iface) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("type mgt subtype beacon");
    config.set_rfmon(true);
    Sniffer sniffer(iface, config);
    sniffer.sniff_loop(make_sniffer_handler(this, &BeaconSniffer::callback));
}
 
bool BeaconSniffer::callback(PDU& pdu) {
    // Get the Dot11 layer
    const Dot11Beacon& beacon = pdu.rfind_pdu<Dot11Beacon>();

    // All beacons must have from_ds == to_ds == 0
    if (!beacon.from_ds() && !beacon.to_ds()) {
        // Get the AP address
        address_type addr = beacon.addr2();
        int ts = beacon.timestamp();
        if (expected_address == addr) {
           cout << "[" << ts << "]" << addr << ": " << beacon.ssid() << "(" << "0" << ")" << endl;
           cout << '\a' << endl;
        }
    }
    return true;
}
 
int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " <<* argv << " <interface>" << endl;
        return 1;
    }
    string interface = argv[1];
    BeaconSniffer sniffer;
    sniffer.run(interface);
}
