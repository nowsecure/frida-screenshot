const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double';
const CGSize: NativeFunctionArgumentType = [CGFloat, CGFloat];

const blocks = new Set();

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
      const application = api.UIApplication.sharedApplication();
      if (application === null) {
        reject(new Error("app not ready"));
        return;
      }

      const block = new ObjC.Block({
        retType: 'void',
        argTypes: [],
        implementation() {
          try {
            const result = action();
            resolve(result);
          } catch (e) {
            reject(e);
          }
          setTimeout(() => blocks.delete(block), 0);
        }
      });
      blocks.add(block);

      application["- _performBlockAfterCATransactionCommits:"](block);
    }
  });
}

interface ImageApi {
  UIApplication: ObjC.Object;
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
      UIApplication: ObjC.classes.UIApplication,
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
