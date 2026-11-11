// A page-sized stand-in for the DOM the shared helpers touch (class, textContent, append, isConnected), on top of fake_dom.mjs.
import {Element, Text} from './fake_dom.mjs';

export class Page extends Element {
  constructor(tag) { super(tag); this.dataset = {}; this.onclick = null; }
  get className() { return this.getAttribute('class') || ''; }
  set className(v) { this.setAttribute('class', v); }
  get classList() { return {add: (c) => { this.className = `${this.className} ${c}`.trim(); }}; }
  set textContent(v) { this.childNodes.splice(0).forEach((c) => { c.parentNode = null; }); if (v !== '') this.appendChild(new Text(v)); }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  get type() { return this.getAttribute('type') || ''; }
  set type(v) { this.setAttribute('type', v); }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); this._connected = false; }
  get isConnected() { return this._connected !== false; }
  append(...kids) { kids.forEach((k) => this.appendChild(typeof k === 'string' ? new Text(k) : k)); }
  replaceChildren(...kids) { this.childNodes.splice(0).forEach((c) => { c.parentNode = null; }); this.append(...kids); }
}
