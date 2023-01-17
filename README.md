# frida-screenshot

Grab screenshots using [Frida](https://frida.re).

## Example

```js
const screenshot = require('frida-screenshot');

const png = await screenshot();
send({
  name: '+screenshot',
  payload: {
    timestamp: Date.now()
  }
}, png);
```
