# Dreamcatcher

Create a graph of mac addresses that are trying to connect to SSIDs.

Build with `make`, run with `./probecatcher`, output grapviz compatable dotfile with `killall -USR1 probecatcher`

Tested on a BeagleboneBlack Rev.C with TP-LINK TL-WN722N.

Requires [libtins](libtins.github.io) and an [updated kernel]()

#### Updating the beaglebone kernel

As root (thanks [datko](http://datko.net/2014/03/21/bbb_upgrade_3_13/))

    curl -OL https://rcn-ee.net/deb/wheezy-armhf/v3.15.6-bone5/install-me.sh
    chmod +x install-me.sh
    ./install-me.sh
    reboot
