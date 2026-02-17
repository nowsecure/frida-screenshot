import ObjC from "frida-objc-bridge";
import { ScreenshotOptions } from "../index.js";

const blocks = new Set();

export function ios(view: ObjC.Object, options: ScreenshotOptions | undefined): Promise<ArrayBuffer> {
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

    const format = api.UIGraphicsImageRendererFormat.preferredFormat();

    const constrainSize = options?.constrainSize;
    if (constrainSize !== undefined) {
      if (typeof constrainSize !== "number" || constrainSize <= 0) {
        throw new Error("Invalid constrainSize value");
      }

      const maxDimension = Math.max(size[0], size[1]);
      const scale: number = format.scale().valueOf();
      if (maxDimension * scale > constrainSize) {
        format.setScale_(constrainSize / maxDimension);
      }
    }

    const renderer = api.UIGraphicsImageRenderer.alloc().initWithSize_format_(size, format).autorelease();
    const actionBlock = new ObjC.Block({
      argTypes: ["object"],
      retType: "void",
      implementation: () => {
        view.drawViewHierarchyInRect_afterScreenUpdates_(bounds, true);
        setTimeout(() => blocks.delete(actionBlock), 0);
      }
    });

    blocks.add(actionBlock);

    const image = renderer.imageWithActions_(actionBlock);
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
        reject(new Error("App not ready"));
        return;
      }

      const block = new ObjC.Block({
        retType: "void",
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
  UIGraphicsImageRendererFormat: ObjC.Object;
  UIGraphicsImageRenderer: ObjC.Object;
  UIImagePNGRepresentation: any;
};

let cachedApi: ImageApi | null = null;
function getApi(): ImageApi {
  if (cachedApi === null) {
    const uikit = Process.getModuleByName("UIKit");
    cachedApi = {
      UIApplication: ObjC.classes.UIApplication,
      UIWindow: ObjC.classes.UIWindow,
      UIGraphicsImageRendererFormat: ObjC.classes.UIGraphicsImageRendererFormat,
      UIGraphicsImageRenderer: ObjC.classes.UIGraphicsImageRenderer,
      NSThread: ObjC.classes.NSThread,
      UIImagePNGRepresentation: new NativeFunction(
          uikit.getExportByName("UIImagePNGRepresentation"),
          "pointer", ["pointer"])
    };
  }
  return cachedApi;
}
