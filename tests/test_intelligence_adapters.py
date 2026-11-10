"""Protocol fixtures for external APIs; no paid external API credentials/calls."""
import json
from urllib.parse import parse_qs,urlsplit
import pytest

from atlas.db import canonical,digest,document
from atlas.policy import Denied
from atlas.tool_registry import IntegrationInput,IntelligenceLookup,MCPToolLookup,create,enable,execute,headers,http_json,intelligence_read,test_connection as probe
from test_tool_management import mcp_server


@pytest.mark.parametrize('adapter,origin,credential,endpoint',[
 ('securitytrails','https://api.securitytrails.com','fixture-secret-st','/v1/domain/example.invalid'),
 ('shodan','https://api.shodan.io','fixture-secret-shodan','/dns/domain/example.invalid'),
 ('censys','https://search.censys.io','fixture-user:fixture-secret-censys','/api/v2/hosts/search'),
 ('virustotal','https://www.virustotal.com','fixture-secret-vt','/api/v3/domains/example.invalid'),
 ('fofa','https://fofa.info','fixture@example.invalid:fixture-secret-fofa','/api/v1/search/all'),
])
def test_fixed_lookup_protocol_and_credential_scrubbing(db,monkeypatch,adapter,origin,credential,endpoint):
    import atlas.tool_registry as registry
    monkeypatch.setattr(registry,'validate_provider_configuration',lambda *_:None)
    seen=[]
    def transport(url,method,**kwargs):
        seen.append((url,method,kwargs))
        assert method=='GET' and urlsplit(url).path==endpoint
        return 200,{},json.dumps({'result':credential,'nested':credential.split(':')[-1]}).encode()
    monkeypatch.setattr(registry,'request',transport)
    row=create(db,'u',IntegrationInput(name=adapter,adapter=adapter,base_url=origin,api_key=credential))
    result=intelligence_read(row,'example.invalid')
    assert credential not in canonical(result) and credential.split(':')[-1] not in canonical(result)
    assert len(seen)==1
    url,_,request=seen[0]
    if adapter=='shodan':assert parse_qs(urlsplit(url).query)['key']==[credential]
    if adapter=='virustotal':assert request['headers']['x-apikey']==credential
    if adapter=='censys':assert request['headers']['Authorization'].startswith('Basic ')
    if adapter=='fofa':assert parse_qs(urlsplit(url).query)['size']==['10']


def test_mcp_reviewed_hostname_tool_and_no_arbitrary_commands(db,mcp_server,monkeypatch):
    import atlas.tool_registry as registry
    url,calls=mcp_server
    row=create(db,'u',IntegrationInput(name='Reviewed lookup fixture',adapter='mcp_resources',base_url=url,api_key='fixture-tool-key',readonly_contract_attested=True,reviewed_tool_names=['lookup_host']))
    assert probe(db,row,'u')['health']=='tested'
    enable(db,row,True,'u')
    scope={'allow':[{'host':'example.invalid'}]}
    policy=document(db,'policy','u',{'scope':scope})
    run=document(db,'run','u',{'policy_id':policy.id,'policy_hash':digest(canonical(scope))})
    monkeypatch.setattr(registry,'authorize',lambda *a,**k:None)
    result=execute(db,run,'mcp_intelligence_lookup',MCPToolLookup(integration_id=row.id,hostname='example.invalid',tool_name='lookup_host'))
    assert 'fixture-tool-key' not in canonical(result)
    before=len(calls)
    with pytest.raises(Denied):execute(db,run,'mcp_intelligence_lookup',MCPToolLookup(integration_id=row.id,hostname='example.invalid',tool_name='delete_database'))
    assert len(calls)==before
