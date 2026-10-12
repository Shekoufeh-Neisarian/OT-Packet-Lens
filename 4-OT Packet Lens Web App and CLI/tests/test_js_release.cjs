// Run: node --test tests/test_js_release.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname, '..');

test('Top Protocols shows packet-count tooltip; Top Talkers remains in MiB', () => {
  const js = fs.readFileSync(path.join(root, 'web/static/js/app.js'), 'utf8');
  const start = js.indexOf('// 2. Top Protocols Bar Chart');
  const finish = js.indexOf('// 3.', start);
  assert(start >= 0 && finish > start);
  assert.match(js.slice(start, finish), /toLocaleString\(\)\} packets/);
  assert.doesNotMatch(js.slice(start, finish), /MiB endpoint traffic/);
  assert.match(js.slice(finish), /MiB endpoint traffic/);
});

function mockTopology() {
  const source = fs.readFileSync(path.join(root, 'web/static/js/topology.js'), 'utf8');
  let next = 1;
  const frames = new Map();
  const events = {};
  const ctx = new Proxy({}, { get(_obj, prop) {
    if (['beginPath','clearRect','moveTo','lineTo','stroke','arc','fill','fillText'].includes(prop)) return () => {};
    return undefined;
  }});
  const canvas = {
    width: 640, height: 420, isConnected: true,
    offsetParent: {}, style: {},
    parentElement: { getBoundingClientRect: () => ({width:640,height:420}) },
    getBoundingClientRect: () => ({left:0,top:0}),
    addEventListener(name,cb){events[name]=cb},
    getContext(){return ctx},
  };
  const globals = {
    document: { getElementById: () => canvas },
    window: {addEventListener(name,cb) { events[name]=cb; }},
    requestAnimationFrame: (cb) => {const id = next++; frames.set(id, cb); return id},
    cancelAnimationFrame: (id) => {frames.delete(id)},
  };
  vm.runInNewContext(source + '\nthis.Topology = NetworkTopology;', globals);
  return { topology: new globals.Topology('graph'), frames, events, tick(max=500) {
    let count=0;
    while(frames.size && count<max){
      const [id,cb] = frames.entries().next().value;
      frames.delete(id);
      cb();count++;
    }
    return count;
  }};
}

test('topology settles after finite frames and resumes after dragging a node', () => {
  const v = mockTopology();
  v.topology.setData({nodes:[{id:'a',label:'A'},{id:'b',label:'B'}],links:[{source:'a',target:'b',value:3}]});
  assert(v.tick() <= 360);
  assert.equal(v.frames.size,0);
  const node = v.topology.nodes[0];
  v.events.mousedown({clientX:node.x,clientY:node.y});
  v.events.mousemove({clientX:node.x+35,clientY:node.y+10});
  v.events.mouseup({});
  assert(v.frames.size > 0, 'drag release should restart a finite layout');
  assert(v.tick() <= 360);
  assert.equal(v.frames.size,0);
});
