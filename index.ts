import ObjC from "frida-objc-bridge";
import { ios } from './lib/ios.js';

const IOS = Symbol('ios');
const UNKNOWN = Symbol('unknown');

export default function screenshot(view: ObjC.Object): Promise<ArrayBuffer> {
  if (getOS() === IOS) {
    return ios(view);
  } else {
    return new Promise(function (_, reject) {
      reject(new Error('Not yet implemented for this OS'));
    });
  }
};

let cachedOS: symbol | null = null;
function getOS() {
  if (cachedOS === null) {
    cachedOS = detectOS();
  }
  return cachedOS;
}

function detectOS(): symbol {
  if (ObjC.available && 'UIView' in ObjC.classes) {
    return IOS;
  } else {
    return UNKNOWN;
  }
}
