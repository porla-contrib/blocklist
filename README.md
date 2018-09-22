# eMule blocklists for Porla

This plugin will download and apply the latest eMule security blocklist when
Porla starts.


## Usage

```js
const { Porla } = require('@porla/porla');
const Blocklist = require('@porla-contrib/blocklist');

const app = new Porla({
    plugins: [ new Blocklist() ]
});
```
