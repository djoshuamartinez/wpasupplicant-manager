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
const {exec} = require('child_process');
const {writeFileSync, readFileSync} = require('fs');
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
        return parseInt(qualityComponents[0]) / parseInt(qualityComponents[1]);
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
            .reduce((object, [key, value]) => ({
                ...object,
                [key]: value
            }), {});

    return output.split('Cell')
        .map(parseCell)
        .filter(c => c.essid); // At least the result must have an essid
};

const toFileContents = networkDetails => {
    const header = 'ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\ncountry=MX\n\n'; // For now it's ok a hardcoded header
    const networkDetailString = detail => {
        let string = '';
        for (const key in detail) {
            string += `\t${key}=${detail[key]}\n`;
        }
        return 'network={\n' + string + '}\n\n';
    };
    return header + networkDetails.map(networkDetailString).join('');
};

const scanNetworks = () => {
    return new Promise((res, rej) => {
        exec("sudo iwlist wlan0 scan", (err, stdout) => {
            if (err) {
                rej(err);
            }
            res(parseIwlistResults(stdout));
        });
    })
};

const entryForNetwork = (essid, securitySettings) => {
    let entry = {};
    entry.ssid = `"${essid}"`;
    if (securitySettings.hidden) {
        entry['scan_ssid'] = '1';
    }
    if (securitySettings.wep) {
        entry['wep_key0'] = `"${securitySettings.password}"`;
        entry['key_mgmt'] = 'NONE';
        return entry;
    }
    if (!securitySettings.password) {
        entry['key_mgmt'] = 'NONE';
        return entry;
    }
    entry.psk = `"${securitySettings.password}"`;
    return entry;
};

const saveNetworkSettings = (essid, securitySettings) => {
    const entry = entryForNetwork(essid, securitySettings);
    const confContents = readFileSync(wpaSupplicantConfFile).toString();
    let configuration = parseConfFile(confContents);

    const entryIndex = configuration.findIndex(c => c.ssid === `"${essid}"`);

    if (entryIndex === -1) {
        configuration.push(entry);
    } else {
        configuration[entryIndex] = entry;
    }
    writeFileSync(wpaSupplicantConfFile, toFileContents(configuration));
};

const forgetNetwork = essid => {
    const confContents = readFileSync(wpaSupplicantConfFile).toString();
    const configuration = parseConfFile(confContents)
        .filter(c => c.ssid !== `"${essid}"`);
    writeFileSync(wpaSupplicantConfFile, toFileContents(configuration));
};

module.exports = {
    scanNetworks,
    saveNetworkSettings,
    forgetNetwork,
};
