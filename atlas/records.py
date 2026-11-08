"""Strict versioned ATLAS Research Record 1.0 conversion contract."""
from typing import Literal
from pydantic import Field
from .policy import Strict
from .db import uid,now
class Source(Strict):
    source_id:str;source_name:str;source_url:str
    source_record_id:str|None=None;author:str|None=None;published_at:str|None=None
    fetched_at:str=Field(default_factory=now);terms_url:str|None=None;license:str='unknown'
    full_text_policy:Literal['allowed','derived_only','metadata_only','unknown_or_restricted']='unknown_or_restricted'
    content_hash_sha256:str=Field(pattern='^[0-9a-f]{64}$');parser_name:str;parser_version:str='1.0'
class Target(Strict):
    vendor:str|None=None;product:str|None=None;component:str|None=None;ecosystem:str|None=None;package:str|None=None
    affected_versions:list=Field(default_factory=list);fixed_versions:list=Field(default_factory=list)
class Classification(Strict):
    cwe:list[str]=[];cve:list[str]=[];ghsa:list[str]=[];osv:list[str]=[];weakness_labels:list[str]=[];owasp_categories:list[str]=[]
    severity_label:str|None=None;cvss_version:str|None=None;cvss_score:float|None=Field(default=None,ge=0,le=10)
class Research(Strict):
    attacker_model:str|None=None;preconditions:list[str]=[];trust_boundary:str|None=None;root_cause:str|None=None
    technical_mechanism:str|None=None;affected_code_path:list[str]=[];impact_claimed_by_source:str|None=None
    reproduction_summary:str|None=None;safe_test_pattern:str|None=None;remediation:str|None=None;patch_references:list[str]=[]
class Evidence(Strict):
    source_claims:list[str]=[];reproduction_available:bool=False;independently_reproduced:bool=False
    validation_status:Literal['source_reported','parsed','reviewed','reproduced','refuted','unknown']='parsed'
class Content(Strict):
    raw_artifact_ref:str|None=None;normalized_text_ref:str|None=None;language:str|None=None
    redaction_status:Literal['not_required','redacted','pending']='not_required'
    chunks:list[dict]=[]
class Deduplication(Strict):
    duplicate_group_id:str|None=None;duplicate_of:str|None=None;source_aliases:list[str]=[]
class Record(Strict):
    schema_name:Literal['atlas-research-record']=Field(default='atlas-research-record',alias='schema')
    atlas_rr_version:Literal['1.0']='1.0'
    record_id:str=Field(default_factory=uid);canonical_key:str
    record_type:Literal['research_report','bug_bounty_disclosure','security_advisory','cve','ghsa','osv','patch_analysis','training_reference']
    title:str=Field(min_length=1);summary:str
    source:Source
    target:Target=Field(default_factory=Target)
    classification:Classification=Field(default_factory=Classification)
    research:Research=Field(default_factory=Research)
    evidence:Evidence=Field(default_factory=Evidence)
    content:Content=Field(default_factory=Content)
    deduplication:Deduplication=Field(default_factory=Deduplication)
    tags:list[str]=[]
    created_at:str=Field(default_factory=now);updated_at:str=Field(default_factory=now)
