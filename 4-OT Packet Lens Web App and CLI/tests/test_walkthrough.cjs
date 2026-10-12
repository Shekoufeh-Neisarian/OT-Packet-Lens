// Dependency-free checks for the optional user guide and short visual README.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

test('website offers an optional, accessible four-step walkthrough', () => {
  const html = read('web/templates/index.html');
  const js = read('web/static/js/app.js');
  for (const id of ['tourOpen','tourWelcomeOpen','tourOverlay','tourDialog','tourPrev','tourNext','tourClose']) {
    assert.match(html, new RegExp('id="' + id + '"'));
  }
  assert.match(html, /role="dialog" aria-modal="true"/);
  assert.match(js, /function setupProductTour\(\)/);
  for (const title of ['Load a capture','Understand the capture','Follow the communication','Export your findings']) assert.ok(js.includes(title));
  assert.match(js, /e.key === "Escape"/);
});

test('README visuals and report links exist', () => {
  const md = read('README.md');
  for (const name of ['docs/assets/dashboard-welcome.png','docs/assets/quick-tour.png','FINAL_ILLUSTRATED_REPORT.pdf','docs/WEBSITE_GUIDE.md']) {
    assert.ok(md.includes(name), name);
    assert.ok(fs.existsSync(path.join(root, name)), name);
  }
  assert.ok(md.includes('python start.py'));
  assert.ok(md.length < 4500, 'README should stay concise');
});
