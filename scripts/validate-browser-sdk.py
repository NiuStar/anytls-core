#!/usr/bin/env python3
"""Validate/apply browser SDK candidate against certified source export only.
No Go, network, module-cache writes or product build are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def sha(b):
    return hashlib.sha256(b).hexdigest()

def main():
    p=argparse.ArgumentParser()
    p.add_argument('source_export',type=Path)
    p.add_argument('--output',required=True,type=Path)
    args=p.parse_args()
    files=json.loads(args.source_export.read_text())
    for entry in files:
        assert sha(entry['text'].encode()) == entry['sha256'], entry['path']
    pins=json.loads((ROOT/'patches/sing-box/browser.identity.json').read_text())
    report={'status':'SOURCE_APPLICATION_ONLY_GO_NOT_RUN','export_files_verified':len(files),'files':[]}
    args.output.mkdir(parents=True,exist_ok=True)
    for pin in pins['files']:
        entry=next(x for x in files if x['path'].endswith('@v1.14.3/'+pin['file']))
        text=entry['text']
        assert sha(text.encode())==pin['source_sha256']
        patch=(ROOT/'patches/sing-box'/pin['patch']).read_bytes()
        assert sha(patch)==pin['patch_sha256']
        for op in json.loads(patch)['replacements']:
            assert text.count(op['old'])==1, (pin['file'],op['old'][:60])
            text=text.replace(op['old'],op['new'],1)
        assert sha(text.encode())==pin['result_sha256']
        target=args.output/pin['file'];target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(text)
        report['files'].append(pin)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
