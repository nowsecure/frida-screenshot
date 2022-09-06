import { ios } from './lib/ios.js';

const IOS = Symbol('ios');
const UNKNOWN = Symbol('unknown');

export default function screenshot(view) {
  if (getOS() === IOS) {
    return ios(view);
  } else {
    return new Promise(function (resolve, reject) {
      reject(new Error('Not yet implemented for this OS'));
    });
  }
};

let cachedOS = null;
function getOS() {
  if (cachedOS === null) {
    cachedOS = detectOS();
  }
  return cachedOS;
}

function detectOS() {
  if (ObjC.available && 'UIView' in ObjC.classes) {
    return IOS;
  } else {
    return UNKNOWN;
  }
}
