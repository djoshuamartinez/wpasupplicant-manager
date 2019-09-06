/*
*  Hidden networks: scan_ssid=1 -> scan with ssid specific request
*
* key_mgmt: list of accepted authenticated key management protocols
# WPA-PSK = WPA pre-shared key (this requires 'psk' field)
# WPA-EAP = WPA using EAP authentication
# IEEE8021X = IEEE 802.1X using EAP authentication and (optionally) dynamically
#	generated WEP keys
# NONE = WPA is not used; plaintext or static WEP could be used
# WPA-PSK-SHA256 = Like WPA-PSK but using stronger SHA256-based algorithms
# WPA-EAP-SHA256 = Like WPA-EAP but using stronger SHA256-based algorithms
# If not set, this defaults to: WPA-PSK WPA-EAP
*
* psk: KEY
*
* ( WEP :
* key_mgmt= NONE
  wep_key0="pass"
  * )
* */

/*

NetworkDetails = {
    essid: String,
    authProtocol: 'wpa'|'none',
    hidden: Bool
}

Network = {
    quality: Integer?
    details: NetworkDetails
}

connect::NetworkDetails->String?->()

list::[Network]
 */

const wpaSupplicantConfFile = '/etc/wpa_supplicant/wpa_supplicant.conf';

const firstGroupMatches = (regex, str) => {
    let m;
    let matches = [];
    while ((m = regex.exec(str)) !== null) {
        if (m.index === regex.lastIndex) {
            regex.lastIndex++;
        }
        if (m[1]) {
            matches.push(m[1]);
        }
    }
    return matches;
};

const parseConfFile = contents => {
    const networkRegex = /network={([^}]*)}/gm;

    const removeTabs = s =>
        s.split('').filter(x => x !== '\t').join('');

    const parseNetworkString = s =>
        s.split('\n')
            .filter(x => x)// Empty strings are false, we don't like empty strings
            .map(removeTabs)
            .reduce((configuration, s) => {
                const values = s.split('=');
                return {
                    ...configuration,
                    [values[0]]: values[1]
                };
            }, {});

    const networkDetails =
        firstGroupMatches(networkRegex, contents)
            .map(parseNetworkString);

    return networkDetails;
};

parseIwlistResults = output => {
    const outputLineOfInterest = l =>
        l.includes('ESSID') || l.includes('Encryption') || l.includes('Quality');

    const parseESSID = l => {
        return l.split(':')[1].slice(1, -1);
    };

    const parseSecurity = l => {
        const toggle = l.split(':')[1];
        return toggle === 'on';
    };

    const parseQuality = l => {
        const startingIndex = l.search('Quality');
        const qualityComponents = l.slice(startingIndex)
            .split(' ')[0]
            .split('=')[1]
            .split('/');
        return parseInt(qualityComponents[0])/parseInt(qualityComponents[1]);
    };

    const parseLineOfInterest = l => {
        if (l.includes('ESSID')) {
            return ['essid', parseESSID(l)];
        }
        if (l.includes('Encryption')) {
            return ['security', parseSecurity(l)];
        }
        if (l.includes('Quality')) {
            return ['quality', parseQuality(l)]
        }
    };

    const parseCell = c =>
        c.split('\n')
            .filter(outputLineOfInterest)
            .map(parseLineOfInterest)
            .reduce((object, [key, value])=>({
                ...object,
                [key]: value
            }), {});

    const networks = output.split('Cell').map(parseCell);
    console.log(networks);
};

const toFileContents = networkDetails => {
    const header = 'ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\ncountry=MX\n\n';
    const networkDetailString = detail => {
        let string = '';
        for(const key in detail){
            string += `\t${key}=${detail[key]}\n`;
        }
        return 'network={\n'+string+'}\n\n';
    };
    return header + networkDetails.map(networkDetailString).join('');
};

parseIwlistResults(`
 wlan0     Scan completed :
          Cell 01 - Address: 30:24:78:AA:65:E5
                    Channel:1
                    Frequency:2.412 GHz (Channel 1)
                    Quality=45/70  Signal level=-65 dBm  
                    Encryption key:on
                    ESSID:"TOTALPLAY_AA65E5"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 18 Mb/s
                              24 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 80ms ago
                    IE: Unknown: 0010544F54414C504C41595F414136354535
                    IE: Unknown: 010882848B962430486C
                    IE: Unknown: 030101
                    IE: Unknown: 07064D5820010B1E
                    IE: Unknown: 200100
                    IE: Unknown: 23021200
                    IE: Unknown: 2A0100
                    IE: Unknown: 32040C121860
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 46053208010000
                    IE: Unknown: 2D1AAD0917FFFFFF0000000000000000000000000000000000000000
                    IE: Unknown: 3D1601080400000000000000000000000000000000000000
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: 7F080500000000000040
                    IE: Unknown: DD820050F204104A0001101044000102103B00010310470010D96C7EFC2F8938F1EFBD6E5148BFA8121021000842726F6164636F6D1023000842726F6164636F6D10240006313233343536104200063132333435361054000800060050F20400011011000A42726F6164636F6D4150100800020004103C0001011049000600372A000120
                    IE: Unknown: DD090010180201005C0000
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101880003A4000027A4000042435E0062322F00
          Cell 02 - Address: B0:4E:26:A4:17:9E
                    Channel:5
                    Frequency:2.432 GHz (Channel 5)
                    Quality=52/70  Signal level=-58 dBm  
                    Encryption key:on
                    ESSID:"The Wi-Fight Club"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 80ms ago
                    IE: Unknown: 00115468652057692D466967687420436C7562
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030105
                    IE: Unknown: 2A0100
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 32043048606C
                    IE: Unknown: 2D1AEE111BFFFFFF0000000000000000000100000000000000000000
                    IE: Unknown: 3D16050D0600000000000000000000000000000000000000
                    IE: Unknown: 7F080000000000000040
                    IE: Unknown: DD180050F2020101800003A4000027A4000042435E0062322F00
                    IE: Unknown: DD0900037F01010000FF7F
                    IE: Unknown: DD990050F204104A0001101044000102103B00010310470010000102030405060708090A0B0C0D0E0F1021000754502D4C494E4B1023000A544C2D57413930314E4410240003352E3010420003312E301054000800060050F204000110110018576972656C657373204E20415020544C2D57413930314E44100800020086103C000101104900140024E26002000101600000020001600100020001
          Cell 03 - Address: 3C:E8:24:D5:85:74
                    Channel:10
                    Frequency:2.457 GHz (Channel 10)
                    Quality=62/70  Signal level=-48 dBm  
                    Encryption key:on
                    ESSID:"Luke, I am your WiFi"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 18 Mb/s
                              24 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 80ms ago
                    IE: Unknown: 00144C756B652C204920616D20796F75722057694669
                    IE: Unknown: 010882848B962430486C
                    IE: Unknown: 03010A
                    IE: Unknown: 07064D5820010D1E
                    IE: Unknown: 2A0104
                    IE: Unknown: 32040C121860
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 0B0504002B0000
                    IE: Unknown: 46053208010000
                    IE: Unknown: 2D1ABC0917FFFF000000000000000000000000000000000000000000
                    IE: Unknown: 3D160A081500000000000000000000000000000000000000
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: 7F03050008
                    IE: Unknown: DD090010180204000C0000
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
          Cell 04 - Address: D0:60:8C:2D:84:57
                    Channel:52
                    Frequency:5.26 GHz (Channel 52)
                    Quality=61/70  Signal level=-49 dBm  
                    Encryption key:on
                    ESSID:"TIDE 5G"
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 18 Mb/s; 24 Mb/s
                              36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 70ms ago
                    IE: Unknown: 000754494445203547
                    IE: Unknown: 01088C129824B048606C
                    IE: Unknown: 030134
                    IE: Unknown: 072A434E202401142801142C01143001143401143801143C01144001149501149901149D0114A10114A50114
                    IE: Unknown: 050400010002
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD310050F204104A000110104400010210470010BC329E001DD811B28601D0608C2D8456103C0001021049000600372A000120
                    IE: Unknown: 2D1A0F0017FFFF000001000000000000000000000000000000000000
                    IE: Unknown: 3D1634050400000000000000000000000000000000000000
                    IE: Unknown: BF0C1000C031FAFF0C03FAFF0C03
                    IE: Unknown: C005013A00FAFF
                    IE: Unknown: 7F080000000000000040
                    IE: Unknown: DD180050F2020101800003A4000027A4000042435E0062322F00
                    IE: Unknown: 200100
                    IE: Unknown: C304020F0F00
                    IE: Unknown: DD07000C4300000000
                    IE: Unknown: DD07000CE700000000
          Cell 05 - Address: D0:60:8C:2D:84:56
                    Channel:11
                    Frequency:2.462 GHz (Channel 11)
                    Quality=66/70  Signal level=-44 dBm  
                    Encryption key:on
                    ESSID:"TIDE"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 9 Mb/s
                              18 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 12 Mb/s; 24 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 70ms ago
                    IE: Unknown: 000454494445
                    IE: Unknown: 010882848B961224486C
                    IE: Unknown: 03010B
                    IE: Unknown: 32040C183060
                    IE: Unknown: 0706434E20010D14
                    IE: Unknown: 33082001020304050607
                    IE: Unknown: 33082105060708090A0B
                    IE: Unknown: 05050001008001
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD310050F204104A000110104400010210470010BC329E001DD811B28601D0608C2D8456103C0001011049000600372A000120
                    IE: Unknown: 2A0104
                    IE: Unknown: 2D1A0E1017FFFF000001000000000000000000000000000000000000
                    IE: Unknown: 3D160B070700000000000000000000000000000000000000
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
                    IE: Unknown: DD07000C4300000000
          Cell 06 - Address: F8:1A:67:68:D1:B2
                    Channel:11
                    Frequency:2.462 GHz (Channel 11)
                    Quality=38/70  Signal level=-72 dBm  
                    Encryption key:on
                    ESSID:"GOPIME"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 6320ms ago
                    IE: Unknown: 0006474F50494D45
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 03010B
                    IE: Unknown: 0706555320010B1B
                    IE: Unknown: 2A0100
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 32043048606C
                    IE: Unknown: 2D1A6E1103FF00000000000000000000000000000000000000000000
                    IE: Unknown: 3D160B071500000000000000000000000000000000000000
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101830003A4000027A4000042435E0062322F00
                    IE: Unknown: DD1E00904C336E1103FF00000000000000000000000000000000000000000000
                    IE: Unknown: DD1A00904C340B071500000000000000000000000000000000000000
                    IE: Unknown: DD0900037F01010000FF7F
                    IE: Unknown: DD990050F204104A0001101044000102103B0001031047001000000000000010000000F81A6768D1101021000754502D4C494E4B10230009544C2D57523734304E10240003342E3010420003312E301054000800060050F204000110110019576972656C65737320526F7574657220544C2D57523734304E100800020086103C000101104900140024E26002000101600000020001600100020001
          Cell 07 - Address: F8:AB:05:42:E8:BC
                    Channel:1
                    Frequency:2.412 GHz (Channel 1)
                    Quality=36/70  Signal level=-74 dBm  
                    Encryption key:on
                    ESSID:"TOTALPLAY_42E8BC"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 18 Mb/s
                              24 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 80ms ago
                    IE: Unknown: 0010544F54414C504C41595F343245384243
                    IE: Unknown: 010882848B962430486C
                    IE: Unknown: 030101
                    IE: Unknown: 07064D5820010B1E
                    IE: Unknown: 200100
                    IE: Unknown: 23021200
                    IE: Unknown: 2A0100
                    IE: Unknown: 32040C121860
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 46053208010000
                    IE: Unknown: 2D1AAD0917FFFFFF0000000000000000000000000000000000000000
                    IE: Unknown: 3D1601080000000000000000000000000000000000000000
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: 7F080500000000000040
                    IE: Unknown: DD820050F204104A0001101044000102103B00010310470010D96C7EFC2F8938F1EFBD6E5148BFA8121021000842726F6164636F6D1023000842726F6164636F6D10240006313233343536104200063132333435361054000800060050F20400011011000A42726F6164636F6D4150100800020004103C0001011049000600372A000120
                    IE: Unknown: DD090010180200005C0000
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101880003A4000027A4000042435E0062322F00
          Cell 08 - Address: 3E:E8:24:D5:85:75
                    Channel:10
                    Frequency:2.457 GHz (Channel 10)
                    Quality=60/70  Signal level=-50 dBm  
                    Encryption key:off
                    ESSID:"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 18 Mb/s
                              24 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 70ms ago
                    IE: Unknown: 000D00000000000000000000000000
                    IE: Unknown: 010882848B962430486C
                    IE: Unknown: 03010A
                    IE: Unknown: 050400010000
                    IE: Unknown: 07064D5820010D1E
                    IE: Unknown: 2A0104
                    IE: Unknown: 32040C121860
                    IE: Unknown: 0B0500002B0000
                    IE: Unknown: 46053208010000
                    IE: Unknown: 2D1ABC0917FFFF000000000000000000000000000000000000000000
                    IE: Unknown: 3D160A081500000000000000000000000000000000000000
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: 7F03050008
                    IE: Unknown: DD090010180200000C0000
                    IE: Unknown: DD180050F2020101800003A4000027A4000042435E0062322F00
          Cell 09 - Address: 2C:9D:1E:EE:32:78
                    Channel:4
                    Frequency:2.427 GHz (Channel 4)
                    Quality=49/70  Signal level=-61 dBm  
                    Encryption key:on
                    ESSID:"Totalplay-6A7F"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 18 Mb/s
                              24 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 80ms ago
                    IE: Unknown: 000E546F74616C706C61792D36413746
                    IE: Unknown: 010882848B962430486C
                    IE: Unknown: 030104
                    IE: Unknown: 050400010002
                    IE: Unknown: 07064D5820010D1E
                    IE: Unknown: 2A0100
                    IE: Unknown: 32040C121860
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 0B0500003D0000
                    IE: Unknown: 46053208010000
                    IE: Unknown: 2D1ABC0917FFFF000000000000000000000000000000000000000000
                    IE: Unknown: 3D1604081100000000000000000000000000000000000000
                    IE: Unknown: 7F03040008
                    IE: Unknown: DD090010180200000C0000
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
          Cell 10 - Address: 70:4F:B8:7D:8E:53
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=37/70  Signal level=-73 dBm  
                    Encryption key:on
                    ESSID:"IZZI-A884"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 9 Mb/s
                              18 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 12 Mb/s; 24 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 80ms ago
                    IE: Unknown: 0009495A5A492D41383834
                    IE: Unknown: 010882848B961224486C
                    IE: Unknown: 030106
                    IE: Unknown: 050400010000
                    IE: Unknown: 0706555320010B1E
                    IE: Unknown: 2A0100
                    IE: Unknown: 32048C98B060
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD310050F204104A000110104400010210470010BC329E001DD811B28601704FB87D8E53103C0001011049000600372A000120
                    IE: Unknown: 0B05000000127A
                    IE: Unknown: 2D1A6F1017FFFFFF0001000000000000000000000000001804871100
                    IE: Unknown: 3D1606000000000000000000000000000000000000000000
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: BF0CB179C233EAFF9204EAFF9204
                    IE: Unknown: C005000000EAFF
                    IE: Unknown: 7F080100080000000000
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
                    IE: Unknown: DD07000C430B000000
                    IE: Unknown: DD21000CE708000000BF0CB101C0332AFF92042AFF9204C0050000002AFFC303010202
          Cell 11 - Address: D0:54:2D:15:61:F0
                    Channel:10
                    Frequency:2.457 GHz (Channel 10)
                    Quality=42/70  Signal level=-68 dBm  
                    Encryption key:on
                    ESSID:"INFINITUME36B"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 12570ms ago
                    IE: Unknown: 000D494E46494E4954554D45333642
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 03010A
                    IE: Unknown: 0706555320010B1B
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 2A0100
                    IE: Unknown: 32043048606C
                    IE: Unknown: DD180050F20201018C0003A4000027A4000042435E0062322F00
                    IE: Unknown: DD1E00904C334C101BFFFF000000000000000000000000000000000000000000
                    IE: Unknown: 2D1A4C101BFFFF000000000000000000000000000000000000000000
                    IE: Unknown: DD1A00904C340A080800000000000000000000000000000000000000
                    IE: Unknown: 3D160A080800000000000000000000000000000000000000
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: 7F0101
                    IE: Unknown: DD0900037F01010000FF7F
                    IE: Unknown: DD0A00037F04010000004000
                    IE: Unknown: DD860050F204104A0001101044000102103B0001031047001000000000000010000000D0542D1561F0102100034349471023000F4349472047504F4E204F4E542052471024000B43494730303030303030311042000831323334353637381054000800060050F20400011011000F4349472047504F4E204F4E54205247100800020082103C000103
          Cell 12 - Address: F4:F2:6D:7A:AB:C2
                    Channel:36
                    Frequency:5.18 GHz (Channel 36)
                    Quality=26/70  Signal level=-84 dBm  
                    Encryption key:on
                    ESSID:"TP-LINK_ABC3_5G"
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 18 Mb/s; 24 Mb/s
                              36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 12570ms ago
                    IE: Unknown: 000F54502D4C494E4B5F414243335F3547
                    IE: Unknown: 01088C129824B048606C
                    IE: Unknown: 030124
                    IE: Unknown: 3C0401162409
                    IE: Unknown: 2D1A6E0016FF00000001000000000000000000000000000000000000
                    IE: Unknown: 3D1624050400000000000000000000000000000000000000
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
                    IE: Unknown: 0B05010001127A
                    IE: Unknown: DD07000C4300000000
                    IE: Unknown: 0706555320240D10
                    IE: Unknown: BF0C2000C031FEFF2401FEFF2401
                    IE: Unknown: C005012A00FEFF
                    IE: Unknown: DD920050F204104A0001101044000102103B0001031047001038833092309218839C77F4F26D7AABC41021000754502D4C494E4B1023000941726368657220433210240003312E3010420003312E301054000800060050F204000110110020414337353020576972656C657373204475616C2042616E64204769676162697410080002210C103C0001021049000600372A000120
          Cell 13 - Address: C8:F8:6D:03:90:DC
                    Channel:11
                    Frequency:2.462 GHz (Channel 11)
                    Quality=38/70  Signal level=-72 dBm  
                    Encryption key:on
                    ESSID:"INFINITUMBF5D"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 6320ms ago
                    IE: Unknown: 000D494E46494E4954554D42463544
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 03010B
                    IE: Unknown: 2A0100
                    IE: Unknown: 32043048606C
                    IE: Unknown: 2D1A2C191EFFFF000000000000000000000000000000000000000000
                    IE: Unknown: 3D160B000100000000000000000000000000000000000000
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : TKIP CCMP
                        Authentication Suites (1) : PSK
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : TKIP CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101800003A4000027A4000042435E0062322F00
                    IE: Unknown: DD1E00904C332C191EFFFF000000000000000000000000000000000000000000
                    IE: Unknown: DD1A00904C340B000100000000000000000000000000000000000000
                    IE: Unknown: DD0600E04C020160
                    IE: Unknown: DD9E0050F204104A0001101044000102103B0001031047001063041253101920061228C8F86D0390DC1021001B5265616C74656B2053656D69636F6E647563746F7220436F72702E1023000752544C387878781024000D45562D323031302D30392D32301042000F3132333435363738393031323334371054000800060050F20400011011000952544B5F41505F32781008000220081049000600372A000120
          Cell 14 - Address: AC:84:C6:A4:05:76
                    Channel:3
                    Frequency:2.422 GHz (Channel 3)
                    Quality=41/70  Signal level=-69 dBm  
                    Encryption key:on
                    ESSID:"Patio"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 9 Mb/s
                              18 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 12 Mb/s; 24 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 80ms ago
                    IE: Unknown: 0005506174696F
                    IE: Unknown: 010882848B961224486C
                    IE: Unknown: 030103
                    IE: Unknown: 2A0104
                    IE: Unknown: 32040C183060
                    IE: Unknown: 2D1A6E1017FFFF000001000000000000000000000000000000000000
                    IE: Unknown: 3D1603050600000000000000000000000000000000000000
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 7F09000000000000000000
                    IE: Unknown: 0B05020000127A
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: DD8F0050F204104A0001101044000102103B0001031047001038833092309218839C77AC84C6A405C41021000754502D4C696E6B1023000A544C2D57413830314E4410240003352E3010420003312E301054000800060050F20400011011001C576972656C657373204E20526F7574657220544C2D57413830314E4410080002210C103C0001011049000600372A000120
                    IE: Unknown: DD07000C4300000000
          Cell 15 - Address: 88:71:B1:9F:8C:5D
                    Channel:11
                    Frequency:2.462 GHz (Channel 11)
                    Quality=41/70  Signal level=-69 dBm  
                    Encryption key:on
                    ESSID:"Velasco"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 9 Mb/s
                              18 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 12 Mb/s; 24 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 12570ms ago
                    IE: Unknown: 000756656C6173636F
                    IE: Unknown: 010882848B961224486C
                    IE: Unknown: 03010B
                    IE: Unknown: 2A0100
                    IE: Unknown: 32048C98B060
                    IE: Unknown: 2D1A6F1017FFFFFF0001000000000000000000000000001804871100
                    IE: Unknown: 3D160B000000000000000000000000000000000000000000
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 6B0100
                    IE: Unknown: 7F09010008800000000000
                    IE: Unknown: 0B05000000127A
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
                    IE: Unknown: 0706555320010B1E
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: Unknown: BF0CB179C233EAFF9204EAFF9204
                    IE: Unknown: C005000000EAFF
                    IE: Unknown: DDA90050F204104A0001101044000102103B00010310470010BC329E001DD811B286018871B19F8C5D1021001852616C696E6B20546563686E6F6C6F67792C20436F72702E1023001C52616C696E6B20576972656C6573732041636365737320506F696E74102400065254323836301042000831323334353637381054000800060050F20400011011000B41525249535F3234474150100800029100103C0001011049000600372A000120
                    IE: Unknown: DD07000C430B000000
                    IE: Unknown: DD21000CE708000000BF0CB101C0332AFF92042AFF9204C0050000002AFFC303010202
          Cell 16 - Address: F4:F2:6D:7A:AB:C3
                    Channel:11
                    Frequency:2.462 GHz (Channel 11)
                    Quality=35/70  Signal level=-75 dBm  
                    Encryption key:on
                    ESSID:"TP-LINK_ABC3"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 9 Mb/s
                              18 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 12 Mb/s; 24 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 6320ms ago
                    IE: Unknown: 000C54502D4C494E4B5F41424333
                    IE: Unknown: 010882848B961224486C
                    IE: Unknown: 03010B
                    IE: Unknown: 32040C183060
                    IE: Unknown: 0706555320010B14
                    IE: Unknown: 33082001020304050607
                    IE: Unknown: 33082105060708090A0B
                    IE: Unknown: 050400010000
                    IE: Unknown: DD310050F204104A00011010440001021047001038833092309218839C77F4F26D7AABC4103C0001011049000600372A000120
                    IE: Unknown: 2A0104
                    IE: Unknown: 2D1A6E1017FFFF000001000000000000000000000000000000000000
                    IE: Unknown: 3D160B000600000000000000000000000000000000000000
                    IE: Unknown: 4A0E14000A002C01C800140005001900
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
                    IE: Unknown: 0B05030023127A
                    IE: Unknown: DD07000C4300000000
          Cell 17 - Address: A8:47:4A:81:C9:D5
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=30/70  Signal level=-80 dBm  
                    Encryption key:on
                    ESSID:"PS4-E831B1A6B450"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0000000000000000
                    Extra: Last beacon: 80ms ago
                    IE: Unknown: 00105053342D453833314231413642343530
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030106
                    IE: Unknown: 05050001000000
                    IE: Unknown: 2A0100
                    IE: Unknown: 2D1A2C1103FFFF000000000000000000000000000000000000000000
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 32043048606C
                    IE: Unknown: 3D1606080000000000000000000000000000000000000000
                    IE: Unknown: DD180050F2020101800003A4000027A4000042435E0062322F00  
`);
console.log(toFileContents(parseConfFile(`ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=MX

network={
	ssid="TIDE"
	scan_ssid=1
	psk="david123"
	key_mgmt=WPA-PSK
}

network={
	ssid="TIDE"
	psk="NoMeLaSe"
}
`)));


const listNetworks = () => {

};
