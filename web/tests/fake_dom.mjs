// A small DOM for the node tests of static/cve/keep-state.js (no jsdom in this repo, and CI installs nothing). It models only what that module and the
// pages' render code touch: elements with attributes, children, replaceChild/insertBefore/removeChild, cloneNode, outerHTML, querySelectorAll over
// "*", "tag", "[attr]", "[attr=value]" and "tag[attr]" (comma separated), details.open, scroll offsets, fields with value/defaultValue, focus.

let ACTIVE = null;
export const activeElement = () => ACTIVE;

// "tag[a][b=v]": the tag, then bracketed attribute tests read one by one (no regular expression over the whole selector)
function matchesOne(el, selector) {
  const text = selector.trim();
  const open = text.indexOf("[");
  const tag = open < 0 ? text : text.slice(0, open);
  if (!/^[a-z0-9*]*$/i.test(tag)) throw new Error(`fake dom: unsupported selector ${selector}`);
  if (el.nodeType !== 1) return false;
  if (tag && tag !== "*" && el.tagName.toLowerCase() !== tag.toLowerCase()) return false;
  let rest = open < 0 ? "" : text.slice(open);
  while (rest) {
    const close = rest.indexOf("]");
    if (!rest.startsWith("[") || close < 0) throw new Error(`fake dom: unsupported selector ${selector}`);
    const [name, value] = rest.slice(1, close).split("=");
    if (!el.hasAttribute(name)) return false;
    if (value !== undefined && el.getAttribute(name) !== value.replace(/^"|"$/g, "")) return false;
    rest = rest.slice(close + 1);
  }
  return true;
}

const escapeText = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");
const escapeAttr = (s) => String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;");

export class Node {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this.parentNode = null;
    this.childNodes = [];
  }
  get firstChild() {
    return this.childNodes[0] || null;
  }
  get nextSibling() {
    if (!this.parentNode) return null;
    const i = this.parentNode.childNodes.indexOf(this);
    return this.parentNode.childNodes[i + 1] || null;
  }
  _detach(node) {
    if (node.parentNode) node.parentNode.childNodes.splice(node.parentNode.childNodes.indexOf(node), 1);
    node.parentNode = null;
  }
  appendChild(node) {
    return this.insertBefore(node, null);
  }
  insertBefore(node, ref) {
    if (node.nodeType === 11) {
      [...node.childNodes].forEach((c) => this.insertBefore(c, ref));
      return node;
    }
    this._detach(node);
    const at = ref ? this.childNodes.indexOf(ref) : this.childNodes.length;
    this.childNodes.splice(at, 0, node);
    node.parentNode = this;
    return node;
  }
  removeChild(node) {
    if (node.parentNode !== this) throw new Error("fake dom: not a child");
    this._detach(node);
    return node;
  }
  replaceChild(next, old) {
    const at = this.childNodes.indexOf(old);
    if (at < 0) throw new Error("fake dom: not a child");
    this._detach(next);
    this.childNodes.splice(this.childNodes.indexOf(old), 1, next);
    old.parentNode = null;
    next.parentNode = this;
    if (ACTIVE && old.contains(ACTIVE)) ACTIVE = null; // a removed element loses focus, as in a browser
    return old;
  }
  contains(other) {
    for (let n = other; n; n = n.parentNode) if (n === this) return true;
    return false;
  }
  get textContent() {
    return this.childNodes.map((c) => c.textContent).join("");
  }
}

export class Text extends Node {
  constructor(text) {
    super(3);
    this.data = String(text);
  }
  get textContent() {
    return this.data;
  }
  cloneNode() {
    return new Text(this.data);
  }
}

export class Fragment extends Node {
  constructor() {
    super(11);
  }
}

export class Element extends Node {
  constructor(tagName) {
    super(1);
    this.tagName = tagName.toUpperCase();
    this.attrs = new Map();
    this.scrollTop = 0;
    this.scrollLeft = 0;
    this._value = undefined;
    this.checked = false;
    this.selectionStart = null;
    this.selectionEnd = null;
  }
  getAttribute(name) {
    return this.attrs.has(name) ? this.attrs.get(name) : null;
  }
  setAttribute(name, value) {
    this.attrs.set(name, String(value));
    if (name === "value" && this._value === undefined) this._value = String(value);
  }
  removeAttribute(name) {
    this.attrs.delete(name);
  }
  hasAttribute(name) {
    return this.attrs.has(name);
  }
  get open() {
    return this.hasAttribute("open");
  }
  set open(on) {
    if (on) this.setAttribute("open", "");
    else this.removeAttribute("open");
  }
  get type() {
    return this.getAttribute("type") || (this.tagName === "INPUT" ? "text" : "");
  }
  get defaultValue() {
    return this.getAttribute("value") || (this.tagName === "TEXTAREA" ? this.textContent : "");
  }
  get value() {
    return this._value === undefined ? this.defaultValue : this._value;
  }
  set value(v) {
    this._value = String(v);
  }
  get defaultChecked() {
    return this.hasAttribute("checked");
  }
  get children() {
    return this.childNodes.filter((c) => c.nodeType === 1);
  }
  matches(selector) {
    return selector.split(",").some((s) => matchesOne(this, s));
  }
  querySelectorAll(selector) {
    const out = [];
    const walk = (n) => {
      for (const c of n.childNodes) {
        if (c.nodeType === 1) {
          if (selector.split(",").some((s) => matchesOne(c, s))) out.push(c);
          walk(c);
        }
      }
    };
    walk(this);
    return out;
  }
  focus() {
    ACTIVE = this;
  }
  setSelectionRange(start, end) {
    this.selectionStart = start;
    this.selectionEnd = end;
  }
  cloneNode(deep) {
    const copy = new Element(this.tagName);
    this.attrs.forEach((v, k) => copy.attrs.set(k, v));
    if (deep) this.childNodes.forEach((c) => copy.appendChild(c.cloneNode(true)));
    return copy;
  }
  get outerHTML() {
    const attrs = [...this.attrs].map(([k, v]) => ` ${k}="${escapeAttr(v)}"`).join("");
    const inner = this.childNodes.map((c) => (c.nodeType === 1 ? c.outerHTML : escapeText(c.data))).join("");
    return `<${this.tagName.toLowerCase()}${attrs}>${inner}</${this.tagName.toLowerCase()}>`;
  }
  addEventListener(type, fn) {
    (this.listeners ||= []).push([type, fn]);
  }
  fire(type) {
    (this.listeners || []).filter(([t]) => t === type).forEach(([, fn]) => fn());
  }
}

/** ``el("details", {"data-keep-key": "x"}, el("summary", {}, "Title"), "text")``; a string child is a text node. */
export function el(tag, attrs = {}, ...kids) {
  const e = new Element(tag);
  Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
  kids.flat().forEach((k) => e.appendChild(typeof k === "string" ? new Text(k) : k));
  return e;
}

/** A document stand-in for the module: the focused element and an empty selection. */
export const doc = {
  get activeElement() {
    return ACTIVE;
  },
  defaultView: { scrollX: 0, scrollY: 0, scrollTo() {}, getSelection: () => ({ isCollapsed: true, anchorNode: null }) },
};

/** Timers the test runs by hand. */
export function fakeTimers() {
  const queue = [];
  let id = 0;
  return {
    queue,
    set: (fn, delay) => {
      id += 1;
      queue.push({ id, fn, delay });
      return id;
    },
    clear: (which) => {
      const i = queue.findIndex((t) => t.id === which);
      if (i >= 0) queue.splice(i, 1);
    },
    runAll() {
      queue.splice(0).forEach((t) => t.fn());
    },
  };
}
