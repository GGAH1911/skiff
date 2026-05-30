//! macOS keyboard input-source (language) change detection.
//!
//! There is no web API to read the OS input source from a webview, so the
//! correct trigger for the terminal's 한/A badge is the actual OS-level
//! input-source change — NOT a hardcoded key. We observe the distributed
//! notification `kTISNotifySelectedKeyboardInputSourceChanged` and, on each
//! change, read the new source's primary language via the Text Input Sources
//! (Carbon) API and emit it to the frontend as `terax://input-source`.
//!
//! No-op on non-macOS.

/// Start observing input-source changes. Call once from Tauri setup (main
/// thread — that is where Tao runs the CFRunLoop that delivers the events).
pub fn start(_app: tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    macos::start(_app);
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{c_void, CStr};
    use std::os::raw::{c_char, c_long};
    use std::ptr;
    use std::sync::OnceLock;

    use tauri::{AppHandle, Emitter};

    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFArrayRef = *const c_void;
    type CFNotificationCenterRef = *const c_void;
    type CFIndex = c_long;
    type Boolean = u8;

    // CFNotificationSuspensionBehaviorDeliverImmediately
    const DELIVER_IMMEDIATELY: CFIndex = 4;
    // kCFStringEncodingUTF8
    const UTF8: u32 = 0x0800_0100;

    type CFNotificationCallback = extern "C" fn(
        center: CFNotificationCenterRef,
        observer: *mut c_void,
        name: CFStringRef,
        object: *const c_void,
        user_info: *const c_void,
    );

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFNotificationCenterGetDistributedCenter() -> CFNotificationCenterRef;
        fn CFNotificationCenterAddObserver(
            center: CFNotificationCenterRef,
            observer: *const c_void,
            callback: CFNotificationCallback,
            name: CFStringRef,
            object: *const c_void,
            suspension_behavior: CFIndex,
        );
        fn CFArrayGetCount(arr: CFArrayRef) -> CFIndex;
        fn CFArrayGetValueAtIndex(arr: CFArrayRef, idx: CFIndex) -> *const c_void;
        fn CFStringGetCString(
            s: CFStringRef,
            buffer: *mut c_char,
            size: CFIndex,
            encoding: u32,
        ) -> Boolean;
        fn CFRelease(cf: CFTypeRef);
    }

    #[link(name = "Carbon", kind = "framework")]
    extern "C" {
        fn TISCopyCurrentKeyboardInputSource() -> CFTypeRef;
        fn TISGetInputSourceProperty(source: CFTypeRef, key: CFStringRef) -> CFTypeRef;
        static kTISPropertyInputSourceLanguages: CFStringRef;
        static kTISNotifySelectedKeyboardInputSourceChanged: CFStringRef;
    }

    static APP: OnceLock<AppHandle> = OnceLock::new();

    pub fn start(app: AppHandle) {
        if APP.set(app).is_err() {
            return; // already started
        }
        unsafe {
            let center = CFNotificationCenterGetDistributedCenter();
            if center.is_null() {
                return;
            }
            CFNotificationCenterAddObserver(
                center,
                ptr::null(),
                on_changed,
                kTISNotifySelectedKeyboardInputSourceChanged,
                ptr::null(),
                DELIVER_IMMEDIATELY,
            );
        }
        // Emit the initial language so the frontend knows the starting state
        // (without flashing — the badge only reacts to subsequent changes).
        emit(true);
    }

    extern "C" fn on_changed(
        _center: CFNotificationCenterRef,
        _observer: *mut c_void,
        _name: CFStringRef,
        _object: *const c_void,
        _user_info: *const c_void,
    ) {
        emit(false);
    }

    fn emit(initial: bool) {
        let Some(app) = APP.get() else { return };
        let lang = current_language();
        let _ = app.emit(
            "terax://input-source",
            serde_json::json!({ "lang": lang, "initial": initial }),
        );
    }

    /// Primary language code of the current keyboard input source, e.g. "ko",
    /// "en", "ja", "zh-Hans". Falls back to "en".
    fn current_language() -> String {
        unsafe {
            let source = TISCopyCurrentKeyboardInputSource();
            if source.is_null() {
                return "en".into();
            }
            let mut lang = "en".to_string();
            let langs =
                TISGetInputSourceProperty(source, kTISPropertyInputSourceLanguages) as CFArrayRef;
            if !langs.is_null() && CFArrayGetCount(langs) > 0 {
                let first = CFArrayGetValueAtIndex(langs, 0) as CFStringRef;
                if !first.is_null() {
                    let mut buf = [0 as c_char; 64];
                    if CFStringGetCString(first, buf.as_mut_ptr(), 64, UTF8) != 0 {
                        lang = CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned();
                    }
                }
            }
            CFRelease(source);
            lang
        }
    }
}
