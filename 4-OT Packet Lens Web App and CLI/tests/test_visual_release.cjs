const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const base = path.resolve(__dirname,'..');
const js = fs.readFileSync(path.join(base,'web/static/js/app.js'),'utf8');
const html = fs.readFileSync(path.join(base,'web/templates/index.html'),'utf8');
test('visual investigation and decoded field bar components are present',()=>{
  assert.match(js,/function renderInvestigation\(report\)/);
  assert.match(js,/function renderAssetActivity\(devices\)/);
  assert.match(js,/operation-fill/);
  assert.match(html,/id="assetActivityVisual"/);
  assert.match(html,/id="insightsGrid"/);
});
test('heuristic anomaly details are not dumped above dashboard tabs',()=>{
  assert.match(js,/className='findings-ribbon'/);
  assert.match(js,/item\(s\) for investigation/);
  assert.match(js,/finding-review/);
});
