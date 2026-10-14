// Frida agent copies document payloads for Python, then lets DZKJ handle them.
// DZKJ retains ownership of the original buffers and loads the document normally.
'use strict';

const DOCUMENT_MESSAGE = 0x4cc;
const DISPATCH_RVA = 0x7f7a0;
const ROOT_HANDLER_RVA = 0x72cb0;
const ROOT_VTABLE_SLOT_RVA = 0x23eee8;
const MANAGER_RVA = 0x89bd0;
const CLEAR_RVA = 0x8d0f0;
const FREE_RVA = 0x1a3680;
const MAX_DOCUMENT = 1024 * 1024 * 1024;
const MAX_NODES = 1048576;
const PART_SIZE = 256 * 1024;
let sequence = 0;
let busy = false;

function sig(address, bytes) {
    const b = new Uint8Array(address.readByteArray(bytes.length));
    for (let i = 0; i < bytes.length; i++) if (b[i] !== bytes[i]) return false;
    return true;
}

function nodeIsNil(p) { return p.add(25).readU8() !== 0; }
function nodePosition(p) { return p.add(32).readU32(); }
function nodeBlob(p) { return p.add(40).readPointer(); }
function nodeLeft(p) { return p.readPointer(); }
function nodeParent(p) { return p.add(8).readPointer(); }
function nodeRight(p) { return p.add(16).readPointer(); }

function nextNode(node, count) {
    let other = nodeRight(node);
    if (other.isNull()) throw new Error('Null tree right link');
    if (!nodeIsNil(other)) {
        node = other;
        for (let n = 0; n <= count; n++) {
            other = nodeLeft(node);
            if (other.isNull()) throw new Error('Null tree left link');
            if (nodeIsNil(other)) return node;
            node = other;
        }
        throw new Error('Cycle in tree left links');
    }
    other = nodeParent(node);
    for (let n = 0; n <= count; n++) {
        if (other.isNull() || nodeIsNil(other) || !node.equals(nodeRight(other))) return other;
        node = other;
        other = nodeParent(other);
    }
    throw new Error('Cycle in tree parent links');
}

function getTree(p) {
    const head = p.readPointer();
    const n64 = p.add(8).readU64();
    const count = Number(n64.toString());
    if (head.isNull() || !Number.isSafeInteger(count) || count < 1 || count > MAX_NODES || !nodeIsNil(head)) {
        throw new Error('Invalid tree head/count');
    }
    return { head, count };
}

function sendPart(id, index, position, ptrValue, size) {
    let offset = 0;
    while (offset < size) {
        const length = Math.min(PART_SIZE, size - offset);
        const bytes = ptrValue.add(offset).readByteArray(length);
        send({ kind: 'document_chunk', id, index, position, size: length }, bytes);
        offset += length;
    }
}

function captureTree(data, id, name, kind, password) {
    const tree = getTree(data);
    // Validate complete tree and all chunk sizes BEFORE sending
    // any captured data. Never alter the application's original data.
    const chunks = [];
    let node = nodeLeft(tree.head);
    let total = 0;
    for (let i = 0; i < tree.count; i++) {
        if (node.isNull() || node.equals(tree.head) || nodeIsNil(node)) throw new Error('Tree node count mismatch');
        const blob = nodeBlob(node);
        const size = blob.readU32();
        if (size < 1 || size > MAX_DOCUMENT - total) throw new Error('Invalid tree chunk size');
        const position = nodePosition(node);
        // Check bounds before collecting the payload.
        blob.add(4).add(size - 1).readU8();
        chunks.push({ blob: blob.add(4), size, position });
        total += size;
        node = nextNode(node, tree.count + 1);
    }
    if (!node.equals(tree.head)) throw new Error('Tree has more nodes than stated');
    send({ kind: 'document_begin', id, name, doc_type: kind, tree: true, count: tree.count, bytes: total, password });
    for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        sendPart(id, i, chunk.position, chunk.blob, chunk.size);
    }
    send({ kind: 'document_end', id });
}

function captureFlat(data, id, name, kind, password) {
    const size = data.readU32();
    if (size < 1 || size > MAX_DOCUMENT) throw new Error('Invalid flat document size');
    data.add(4).add(size - 1).readU8();
    send({ kind: 'document_begin', id, name, doc_type: kind, tree: false, count: 1, bytes: size, password });
    sendPart(id, 0, 0, data.add(4), size);
    send({ kind: 'document_end', id });
}

try {
    const main = Process.mainModule;
    if (Process.arch !== 'x64' || main.name.toLowerCase() !== 'dzkj.exe') {
        throw new Error('Expected a native 64-bit DZKJ.exe process');
    }
    const base = main.base;
    const pe = base.add(base.add(0x3c).readU32());
    if (pe.readU32() !== 0x4550 || pe.add(4).readU16() !== 0x8664 || pe.add(24 + 56).readU32() !== 0x818000) {
        throw new Error('Executable image layout differs from the supported DZKJ build');
    }
    if (!sig(base.add(DISPATCH_RVA), [0x40,0x55,0x53,0x56,0x57,0x41,0x54,0x41,0x56,0x41,0x57,0x48,0x8b,0xec,0x48,0x81,0xec,0x80,0,0,0]) ||
        !sig(base.add(ROOT_HANDLER_RVA), [0x40,0x53,0x55,0x56,0x57,0x48,0x83,0xec,0x48,0x49,0x8b,0xe9,0x49,0x8b,0xf8,0x48,0x8b,0xf1,0x81,0xfa,0x04,0x04,0,0]) ||
        !sig(base.add(MANAGER_RVA), [0x48,0x89,0x5c,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x57,0x48,0x83,0xec,0x50]) ||
        !sig(base.add(CLEAR_RVA), [0x48,0x89,0x5c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57,0x48,0x83,0xec,0x20]) ||
        !sig(base.add(FREE_RVA), [0xe9,0xab,0x35,0xeb,0xff]) ||
        !base.add(ROOT_VTABLE_SLOT_RVA).readPointer().equals(base.add(ROOT_HANDLER_RVA))) {
        throw new Error('Native handler or ownership signatures did not match');
    }
    const clientManager = new NativeFunction(base.add(MANAGER_RVA), 'pointer', []);
    const signature = ['pointer', 'uint64', 'pointer', 'pointer'];
    let originalRootHandler = null;
    const replacement = new NativeCallback(function (window, message, data, metadata) {
        if (message.toNumber() !== DOCUMENT_MESSAGE || data.isNull() || metadata.isNull() || busy) {
            return originalRootHandler(window, message, data, metadata);
        }
        busy = true;
        const id = ++sequence;
        let forwarded = false;
        try {
            const kind = metadata.add(16).readU32();
            if (kind < 1 || kind > 5 || kind === 4) {
                return originalRootHandler(window, message, data, metadata);
            }
            const filenamePointer = metadata.readPointer();
            if (filenamePointer.isNull()) return originalRootHandler(window, message, data, metadata);
            const name = filenamePointer.readUtf16String();
            if (!name || name.length > 32767) return originalRootHandler(window, message, data, metadata);
            let password = null;
            if (kind === 2) {
                const passwordPointer = metadata.add(24).readPointer();
                if (!passwordPointer.isNull()) {
                    const n = passwordPointer.readU32();
                    if (n > 0 && n <= 4096) {
                        const p = new Uint8Array(passwordPointer.add(4).readByteArray(n));
                        if (p.every(x => x !== 0 && x !== 10 && x !== 13)) password = String.fromCharCode.apply(null, p);
                    }
                }
            }
            let manager = null;
            if (kind === 1) {
                const tree = getTree(data);
                manager = clientManager();
                if (manager.isNull() || !manager.add(0x70).readPointer().equals(tree.head)) {
                    throw new Error('PCB owner did not match the client manager');
                }
                captureTree(data, id, name, kind, password);
            } else {
                captureFlat(data, id, name, kind, password);
            }
            // The captured bytes have already been copied into Frida messages.
            // Forward the original pointers so DZKJ can load the document and
            // retain responsibility for freeing its tree or flat buffer.
            forwarded = true;
            return originalRootHandler(window, message, data, metadata);
        } catch (e) {
            send({ kind: 'document_error', id, message: String(e) });
            if (forwarded) return 1;
            return originalRootHandler(window, message, data, metadata);
        } finally {
            busy = false;
        }
    }, 'int64', signature);
    const originalRootAddress = Interceptor.replaceFast(base.add(ROOT_HANDLER_RVA), replacement);
    originalRootHandler = new NativeFunction(originalRootAddress, 'int64', signature);
    Interceptor.flush();
    send({ kind: 'ready', pid: Process.id, base: base.toString() });
} catch (e) {
    send({ kind: 'init_error', message: String(e) });
}
