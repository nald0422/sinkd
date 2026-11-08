// The start of every scriptlet file, before the library: the page's host
// keys, and a cheap check that this file has calls for any of them. Most
// files run only on their own sites, but the entity file runs on every
// page, so the check has to cost next to nothing; the library is only
// parsed lazily and run when it passes.
//
// The compiler puts `data` (the file's table, as a JSON string) and
// `suffixes` (two-label public suffixes) in front of this. Like the
// library, nothing here may name the extension.

// The keys a hostname is listed under: itself, its parents, and entities
// (`example.*`). Mirrors host_keys in crates/core/src/page.rs.
const pageKeys = (hostname) => {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === '') {
    return [];
  }
  const labels = host.split('.');
  const keys = [];
  for (let i = 0; i < labels.length; i++) {
    keys.push(labels.slice(i).join('.'));
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':') || labels.length < 2) {
    return keys;
  }
  const lastTwo = labels.slice(-2).join('.');
  const suffix = labels.length > 2 && suffixes.indexOf(lastTwo) !== -1 ? 2 : 1;
  const rest = labels.slice(0, labels.length - suffix);
  for (let i = 0; i < rest.length; i++) {
    keys.push(`${rest.slice(i).join('.')}.*`);
  }
  return keys;
};

let hostname = self.location.hostname;
if (hostname === '') {
  // about:blank and srcdoc frames act for the page that made them.
  try {
    hostname = new URL(self.origin).hostname;
  } catch (e) {
    hostname = '';
  }
}
const keys = pageKeys(hostname);
// Keys appear in `data` as quoted JSON strings; a call argument that
// happens to match only costs a full lookup.
if (!keys.some((key) => data.indexOf(`"${key}"`) !== -1)) {
  return;
}
