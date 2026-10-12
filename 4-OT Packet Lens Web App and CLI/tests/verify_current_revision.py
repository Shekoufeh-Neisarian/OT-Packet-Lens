import sys,json,tempfile,pathlib,dpkt
r=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(r))
from analyzer import PcapAnalyzer,ReportExporter
results={}
for p in sorted((r/'pcaps/samples').glob('*.pcap')):
 a=PcapAnalyzer(str(p)).analyze()
 results[p.name]={'packets':a['summary']['packet_count'],'endpoints':a['summary']['device_count'],'protocols':a['detected_protocols'],'insights':{k:v for k,v in a['protocol_insights'].items() if any(v[x] for x in ['function_codes','operations','unit_ids','service_codes','device_identifiers','asdu_types'])}}
 for meth in ['to_json','to_csv_devices','to_csv_conversations','to_markdown','to_html']:
  assert getattr(ReportExporter,meth)(a)
 if p.name.startswith('BACnet'):
  for ext,meth in [('json','to_json'),('md','to_markdown'),('html','to_html'),('devices.csv','to_csv_devices'),('flows.csv','to_csv_conversations')]:
   name=f'{p.stem}_{ext}' if ext.endswith('csv') else f'{p.stem}_report.{ext}'
   (r/'reports'/name).write_text(getattr(ReportExporter,meth)(a),encoding='utf-8')
with tempfile.TemporaryDirectory() as td:
 t=pathlib.Path(td)
 for name,content in [('empty.pcap',b''),('invalid.pcap',b'not a capture')]:
  (t/name).write_bytes(content)
  try:PcapAnalyzer(str(t/name)).analyze();raise AssertionError(name)
  except ValueError:pass
 try:PcapAnalyzer(str(t/'missing.pcap')).analyze();raise AssertionError('missing')
 except FileNotFoundError:pass
 with (r/'pcaps/samples/dnp3_assign_class.pcap').open('rb') as src,(t/'valid.pcapng').open('wb') as dst:
  writer=dpkt.pcapng.Writer(dst)
  for ts,pkt in dpkt.pcap.Reader(src):writer.writepkt(pkt,ts)
 assert PcapAnalyzer(str(t/'valid.pcapng')).analyze()['summary']['packet_count']==3
results['checks']={'invalid_empty_missing':'PASS','pcapng':'PASS (3 packets)','export_formats':'all five methods nonempty for seven samples'}
(r/'docs/verification_results.json').write_text(json.dumps(results,indent=2))
print(json.dumps({k:{x:v[x] for x in ['packets','endpoints','protocols']} for k,v in results.items() if k!='checks'},indent=2))
