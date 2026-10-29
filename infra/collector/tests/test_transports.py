#!/usr/bin/env python3
"""Local-only replay, mTLS, and diagnostic feedback-boundary tests."""
import copy
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import yaml
from test_distribution import BINARY, ROOT, CWL, rendered_configs


def wait_for(predicate, process=None, timeout=15):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if predicate(): return
        if process is not None and process.poll() is not None: break
        time.sleep(.1)
    raise AssertionError('Fixture condition not reached before deadline')


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try: process.wait(timeout=8)
        except subprocess.TimeoutExpired: process.kill();process.wait()


def start(config, tmp, label):
    path=tmp/(label+'.yaml');path.write_text(yaml.safe_dump(config))
    errors=(tmp/(label+'.stderr')).open('w')
    process=subprocess.Popen([BINARY,'--config='+str(path)],env=dict(os.environ,AWS_ACCESS_KEY_ID='fixture-key-not-real',AWS_SECRET_ACCESS_KEY='fixture-secret-not-real',AWS_EC2_METADATA_DISABLED='true'),stdout=errors,stderr=errors)
    errors.close()
    return process


def fixture_config(tmp, source, receiver='filelog/fixture'):
    cfg=rendered_configs()['runsecure-telemetry-gateway']
    cfg['extensions']={'file_storage':{'directory':str(tmp/'storage'),'create_directory':True}}
    cfg['receivers']={receiver:{'include':[str(source)],'start_at':'beginning','storage':'file_storage','resource':{'rs.source.class':'collector'},'retry_on_failure':{'enabled':True,'max_elapsed_time':'0s'}}}
    cfg['processors']['cornerstone_validator']['signatures']['file']=str(ROOT/'.cornerstone/events')
    cfg['service']['extensions']=['file_storage']
    cfg['service']['pipelines']={'logs':{'receivers':[receiver],'processors':cfg['service']['pipelines']['logs']['processors'],'exporters':['awscloudwatchlogs']}}
    cfg['service']['telemetry']={'logs':{'level':'warn','encoding':'json','output_paths':[str(tmp/'diagnostics.json')]},'metrics':{'level':'none','readers':[]}}
    del cfg['exporters']['awscloudwatchlogs/diagnostics']
    return cfg


def file_records(path):
    if not path.exists(): return []
    result=[]
    for line in path.read_text().splitlines():
        if not line:continue
        try: document=json.loads(line)
        except json.JSONDecodeError:continue
        for resource in document.get('resourceLogs',[]):
            for scope in resource.get('scopeLogs',[]):
                result.extend(scope.get('logRecords',[]))
    return result


class FlakyCWL(CWL):
    offline=True
    failed=0
    def do_POST(self):
        if type(self).offline:
            self.rfile.read(int(self.headers['Content-Length']))
            type(self).failed+=1
            body=b'{"__type":"ServiceUnavailableException","message":"fixture outage"}'
            self.send_response(503);self.send_header('Content-Type','application/x-amz-json-1.1');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        else:super().do_POST()


@unittest.skipUnless(BINARY,'Set COLLECTOR_BINARY to the assembled binary')
class TransportFixture(unittest.TestCase):
    def test_persistent_cwl_queue_survives_outage_stop_restart_without_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp=Path(temporary);source=tmp/'source.log';source.write_text('restart-queue-marker\n')
            FlakyCWL.offline=True;FlakyCWL.failed=0;FlakyCWL.records=[];FlakyCWL.requests=[]
            server=http.server.HTTPServer(('127.0.0.1',0),FlakyCWL)
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            cfg=fixture_config(tmp,source)
            cfg['exporters']['awscloudwatchlogs']['endpoint']=f'http://127.0.0.1:{server.server_port}'
            cfg['exporters']['awscloudwatchlogs']['retry_on_failure']['max_interval']='2s'
            process=start(cfg,tmp,'first')
            try:
                wait_for(lambda:FlakyCWL.failed>0,process)
                self.assertEqual([],FlakyCWL.records)
                stop(process)
                source.unlink() # replay must come from persistent queue, not reread
                FlakyCWL.offline=False
                process=start(cfg,tmp,'second')
                wait_for(lambda:bool(FlakyCWL.records),process,timeout=25)
                self.assertIn('restart-queue-marker',json.dumps(FlakyCWL.records))
                self.assertTrue(any((tmp/'storage').iterdir()))
            finally:stop(process);server.shutdown();server.server_close();worker.join(timeout=2)

    def test_self_diagnostics_filter_uses_real_logger_component_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp=Path(temporary);source=tmp/'source.log';source.write_text('diagnostic-main-marker\n')
            cfg=fixture_config(tmp,source)
            # A real exporter failure emits the same JSON logger component keys
            # the deployed self-pipeline filters, without contacting AWS.
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1',0));unavailable_port=reservation.getsockname()[1]
            cfg['exporters']={'otlp/diagnostics':{'endpoint':f'127.0.0.1:{unavailable_port}','tls':{'insecure':True},'timeout':'1s','sending_queue':{'enabled':False},'retry_on_failure':{'enabled':False}}}
            cfg['service']['pipelines']['logs']['exporters']=['otlp/diagnostics']
            process=start(cfg,tmp,'logger')
            try:
                wait_for(lambda:(tmp/'diagnostics.json').exists() and '"otelcol.component.id": "otlp/diagnostics"' in (tmp/'diagnostics.json').read_text().replace(':', ': '),process)
                logs=[json.loads(line) for line in (tmp/'diagnostics.json').read_text().splitlines() if line]
                keyed=[line for line in logs if line.get('otelcol.component.id')=='otlp/diagnostics']
                self.assertTrue(keyed,logs)
                actual=keyed[0]
            finally:stop(process)
            records=[]
            # Match exact parsed IDs; a user message mentioning an exporter is
            # not an exclusion. Missing component keys also remain observable.
            for component in ['awscloudwatchlogs','awscloudwatchlogs/diagnostics','filelog/self','unrelated']:
                item=copy.deepcopy(actual);item['otelcol.component.id']=component;item['msg']='diagnostic-marker-'+component;records.append(item)
            records.append({'msg':'mentions awscloudwatchlogs/diagnostics but has no component id'})
            source.write_text(''.join(json.dumps(r)+'\n' for r in records))
            cfg=fixture_config(tmp/'filter',source,'filelog/self')
            (tmp/'filter').mkdir()
            receiver=rendered_configs()['runsecure-telemetry-gateway']['receivers']['filelog/self']
            cfg['receivers']['filelog/self']['operators']=receiver['operators']
            output=tmp/'filtered.json'
            cfg['exporters']={'file':{'path':str(output),'flush_interval':'100ms'}}
            cfg['service']['pipelines']['logs']['exporters']=['file']
            process=start(cfg,tmp,'filter')
            try:
                wait_for(lambda:len(file_records(output))>=3,process)
                stop(process)
                text=output.read_text()
                self.assertEqual(3,len(file_records(output)))
                self.assertIn('diagnostic-marker-awscloudwatchlogs',text)
                self.assertIn('diagnostic-marker-unrelated',text)
                self.assertNotIn('diagnostic-marker-awscloudwatchlogs/diagnostics',text)
                self.assertNotIn('diagnostic-marker-filelog/self',text)
            finally:stop(process)

    def test_mtls_rejects_missing_client_certificate_then_accepts_agent(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp=Path(temporary)
            def openssl(*args):subprocess.run(['openssl',*args],check=True,capture_output=True)
            openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tmp/'ca.key'),'-out',str(tmp/'ca.crt'),'-days','1','-subj','/CN=fixture-agent-ca')
            for name,usage in [('server','serverAuth'),('client','clientAuth')]:
                openssl('req','-newkey','rsa:2048','-nodes','-keyout',str(tmp/(name+'.key')),'-out',str(tmp/(name+'.csr')),'-subj','/CN=fixture-'+name)
                ext=tmp/(name+'.ext');ext.write_text('extendedKeyUsage='+usage+'\nsubjectAltName=IP:127.0.0.1\n')
                openssl('x509','-req','-in',str(tmp/(name+'.csr')),'-CA',str(tmp/'ca.crt'),'-CAkey',str(tmp/'ca.key'),'-CAcreateserial','-out',str(tmp/(name+'.crt')),'-days','1','-extfile',str(ext))
            with socket.socket() as reservation:reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
            output=tmp/'gateway.json'
            gateway=fixture_config(tmp/'gateway',tmp/'unused')
            (tmp/'gateway').mkdir()
            gateway['receivers']={'otlp':{'protocols':{'grpc':{'endpoint':f'127.0.0.1:{port}','tls':{'cert_file':str(tmp/'server.crt'),'key_file':str(tmp/'server.key'),'client_ca_file':str(tmp/'ca.crt'),'min_version':'1.3'}}}}}
            gateway['exporters']={'file':{'path':str(output),'flush_interval':'100ms'}}
            gateway['service']['pipelines']['logs']['receivers']=['otlp'];gateway['service']['pipelines']['logs']['exporters']=['file']
            server=start(gateway,tmp,'gateway')
            source=tmp/'source.log';source.write_text('mtls-positive-marker\n')
            agent=fixture_config(tmp/'agent',source)
            (tmp/'agent').mkdir()
            agent['processors']={'runsecure_normalize/redact':{'environment':'Testing','max_body_bytes':65536,'redact_only':True}}
            agent['exporters']={'otlp':{'endpoint':f'127.0.0.1:{port}','tls':{'ca_file':str(tmp/'ca.crt'),'min_version':'1.3'},'sending_queue':{'enabled':True,'storage':'file_storage','queue_size':16},'retry_on_failure':{'enabled':True,'initial_interval':'1s','max_interval':'2s','max_elapsed_time':'0s'}}}
            agent['service']['pipelines']['logs']['processors']=['runsecure_normalize/redact'];agent['service']['pipelines']['logs']['exporters']=['otlp']
            client=None
            try:
                def listening():
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):return True
                    except OSError:return False
                wait_for(listening,server)
                client=start(agent,tmp,'bad-client')
                time.sleep(2)
                self.assertEqual([],file_records(output),'missing client cert must not deliver logs')
                stop(client)
                agent['exporters']['otlp']['tls'].update(cert_file=str(tmp/'client.crt'),key_file=str(tmp/'client.key'))
                client=start(agent,tmp,'good-client')
                wait_for(lambda:bool(file_records(output)),client)
                self.assertIn('mtls-positive-marker',output.read_text())
            finally:
                if client is not None:stop(client)
                stop(server)


if __name__=='__main__':unittest.main()
