// Polyfill requestAnimationFrame / cancelAnimationFrame for jsdom environment.
// jsdom provides stubs that throw, so we unconditionally override them.

let _rafId = 0;
const _rafCallbacks = new Map();

globalThis.requestAnimationFrame = (callback) => {
    const id = ++_rafId;
    _rafCallbacks.set(id, setTimeout(() => {
        _rafCallbacks.delete(id);
        callback(performance.now());
    }, 0));
    return id;
};

globalThis.cancelAnimationFrame = (id) => {
    const timer = _rafCallbacks.get(id);
    if (timer !== undefined) {
        clearTimeout(timer);
        _rafCallbacks.delete(id);
    }
};
