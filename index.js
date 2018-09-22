const request = require('request');
const split = require('split');
const unzip = require('unzip');
const { Plugin, Porla } = require('@porla/porla');

const url = 'http://upd.emule-security.org/ipfilter.zip';

async function applyBlocklist(session) {
    return new Promise((resolve, reject) => {
        request(url)
            .pipe(unzip.Parse())
            .on('entry', (entry) => {
                if (entry.path !== 'guarding.p2p') {
                    return entry.autodrain();
                }

                const filter = session.get_ip_filter();

                entry
                    .pipe(split())
                    .on('end', () => {
                        session.set_ip_filter(filter);
                        resolve();
                    })
                    .on('error', (err) => reject(err))
                    .on('data', (d) => {
                        if (d.length < 33) {
                            return;
                        }

                        const from = d.substr(0, 15).replace(/\b0+\B/g, '');
                        const to = d.substr(18, 15).replace(/\b0+\B/g, '');

                        filter.add_rule(from, to, 1);
                    });
            });
    });
}

class Blocklist extends Plugin {
    /**
     * 
     * @param {Porla} porla
     */
    load(porla) {
        porla.subscribe('session.init', [
            (session) => applyBlocklist(session)
        ]);
    }
}

module.exports = Blocklist;
