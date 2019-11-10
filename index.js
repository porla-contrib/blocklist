const request = require('request');
const split = require('split');
const unzipper = require('unzipper');

const DEFAULT_URL = 'http://upd.emule-security.org/ipfilter.zip';

function applyBlocklist(url, { log }, session) {
    return new Promise((resolve, reject) => {
        log.info('Downloading blocklist from %s', url);

        // TODO: save zip file to state directory

        request(url)
            .pipe(unzipper.Parse())
            .on('entry', (entry) => {
                if (entry.path !== 'guarding.p2p') {
                    return entry.autodrain();
                }

                const filter = session.get_ip_filter();
                let count = 0;

                entry
                    .pipe(split())
                    .on('end', () => {
                        session.set_ip_filter(filter);
                        log.info('Added %d address(es) to IP filter', count);
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

                        count += 1;
                    });
            });
    });
}

function blocklist(options) {
    options = options || {};

    return function(porla) {
        porla.on('session.init', async ({ session }) => {
            await applyBlocklist(
                options.url || DEFAULT_URL,
                porla,
                session.native());
        });
    }
}

module.exports = blocklist;
