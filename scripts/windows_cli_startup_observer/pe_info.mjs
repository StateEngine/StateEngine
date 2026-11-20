import assert from 'node:assert/strict';
import fs from 'node:fs';
const [file, output] = process.argv.slice(2);
const b = fs.readFileSync(file), u16 = o => b.readUInt16LE(o), u32 = o => b.readUInt32LE(o);
assert.equal(b.toString('ascii', 0, 2), 'MZ');
const pe = u32(0x3c); assert.equal(b.toString('binary', pe, pe + 4), 'PE\0\0');
const sectionCount = u16(pe + 6), optionalSize = u16(pe + 20), opt = pe + 24;
const magic = u16(opt), wide = magic === 0x20b;
assert(wide || magic === 0x10b);
const directories = opt + (wide ? 112 : 96), sectionStart = opt + optionalSize;
const sections = Array.from({ length: sectionCount }, (_, index) => {
  const at = sectionStart + index * 40;
  return { name: b.toString('ascii', at, at + 8).replace(/\0.*$/, ''),
    virtual_size: u32(at + 8), address: u32(at + 12), raw_size: u32(at + 16), raw: u32(at + 20) };
});
function offset(rva) {
  const s = sections.find(s => rva >= s.address && rva < s.address + Math.max(s.virtual_size, s.raw_size));
  assert(s, `Unmapped RVA ${rva}`);
  const at = s.raw + rva - s.address; assert(at < b.length); return at;
}
function string(rva) {
  const at = offset(rva), end = b.indexOf(0, at); assert(end >= at); return b.toString('ascii', at, end);
}
const importRva = u32(directories + 8), imports = [];
if (importRva) {
  for (let at = offset(importRva); ; at += 20) {
    const lookup = u32(at), name = u32(at + 12), address = u32(at + 16);
    if (!(lookup || name || address)) break;
    const table = offset(lookup || address), stride = wide ? 8 : 4;
    let symbols = 0;
    while (wide ? b.readBigUInt64LE(table + symbols * stride) !== 0n : u32(table + symbols * stride) !== 0) symbols++;
    imports.push({ module: string(name), symbols });
  }
}
const delayRva = u32(directories + 13 * 8), delayedImports = [];
if (delayRva) {
  for (let at = offset(delayRva); ; at += 32) {
    const flags = u32(at), name = u32(at + 4), lookup = u32(at + 16);
    if (!name && !lookup) break;
    assert.equal(flags & 1, 1, 'Expected RVA-based delayed imports');
    const table = offset(lookup), stride = wide ? 8 : 4;
    let symbols = 0;
    while (wide ? b.readBigUInt64LE(table + symbols * stride) !== 0n : u32(table + symbols * stride) !== 0) symbols++;
    delayedImports.push({ module: string(name), symbols });
  }
}
const info = { file_bytes: b.length, image_bytes: u32(opt + 56), sections,
  relocation_directory_bytes: u32(directories + 5 * 8 + 4), imports, delayed_imports: delayedImports };
fs.writeFileSync(output, JSON.stringify(info, null, 2) + '\n');
