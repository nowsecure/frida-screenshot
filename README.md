# frida-screenshot

Grab screenshots using [Frida](http://frida.re).

## Example

```js
const screenshot = require('frida-screenshot');

const png = yield screenshot();
send({
  name: '+screenshot',
  payload: {
    timestamp: Date.now()
  }
}, png);
```
