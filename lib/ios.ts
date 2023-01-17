const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double';
const CGSize: NativeFunctionArgumentType = [CGFloat, CGFloat];

export function ios(view: ObjC.Object): Promise<ArrayBuffer> {
  return performOnMainThread(() => {
    const api = getApi() as any;
    if (api === null) {
      throw new Error("Cannot retrieve the API");
    }

    if (!view) {
      view = api.UIWindow.keyWindow();
    }

    const bounds = view.bounds();
    const size = bounds[1];
    api.UIGraphicsBeginImageContextWithOptions(size, 0, 0);

    view.drawViewHierarchyInRect_afterScreenUpdates_(bounds, true);

    const image = api.UIGraphicsGetImageFromCurrentImageContext();
    api.UIGraphicsEndImageContext();

    const png = new ObjC.Object(api.UIImagePNGRepresentation(image));
    const data: NativePointer = png.bytes();
    return data.readByteArray(png.length())!;
  });
};

function performOnMainThread<R>(action: () => R): Promise<R> {
  return new Promise((resolve, reject) => {
    const api = getApi();
    if (api.NSThread.isMainThread()) {
      performAction();
    } else {
      ObjC.schedule(ObjC.mainQueue, performAction);
    }

    function performAction() {
      try {
        const result = action();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    }
  });
}

interface ImageApi {
  UIWindow: ObjC.Object;
  NSThread: ObjC.Object;
  UIGraphicsBeginImageContextWithOptions: any;
  UIGraphicsEndImageContext: any;
  UIGraphicsGetImageFromCurrentImageContext: any;
  UIImagePNGRepresentation: any;
};

let cachedApi: ImageApi | null = null;
function getApi(): ImageApi {
  if (cachedApi === null) {
    cachedApi = {
      UIWindow: ObjC.classes.UIWindow,
      NSThread: ObjC.classes.NSThread,
      UIGraphicsBeginImageContextWithOptions: new NativeFunction(
          Module.getExportByName('UIKit', 'UIGraphicsBeginImageContextWithOptions'),
          'void', [CGSize, 'bool', CGFloat]),
      UIGraphicsEndImageContext: new NativeFunction(
          Module.getExportByName('UIKit', 'UIGraphicsEndImageContext'),
          'void', []),
      UIGraphicsGetImageFromCurrentImageContext: new NativeFunction(
          Module.getExportByName('UIKit', 'UIGraphicsGetImageFromCurrentImageContext'),
          'pointer', []),
      UIImagePNGRepresentation: new NativeFunction(
          Module.getExportByName('UIKit', 'UIImagePNGRepresentation'),
          'pointer', ['pointer'])
    };
  }
  return cachedApi;
}
