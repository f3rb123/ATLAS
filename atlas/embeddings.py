"""Verified, pinned local ONNX semantic embeddings; explicit lexical fallback for tests/offline mode."""
import hashlib,json,re,os
from functools import lru_cache
from pathlib import Path
import numpy as np
from .config import settings

HASH_MODEL='signed-token-hash-v1-128'
def manifest():return json.loads((Path(__file__).parent/'data'/'embedding_model.json').read_text())
def embedding_version():
    if settings().embedding_model=='hash':return HASH_MODEL
    m=manifest()
    if settings().embedding_model!=m['model']:raise ValueError('Embedding model is not in the verified pinned registry')
    return m['model']+'@'+m['revision']
def dimension():return 128 if settings().embedding_model=='hash' else manifest()['dimension']
def cache_root():return Path(settings().embedding_cache_dir or str(Path(settings().data_dir)/'models'))

def verify_model():
    m=manifest();root=cache_root()/m['snapshot_relative_path']
    for name,expected in m['files_sha256'].items():
        p=root/name
        if not p.is_file():raise ValueError('Semantic embedding weights missing; run atlas host embeddings-prepare')
        h=hashlib.sha256()
        with p.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
        if h.hexdigest()!=expected:raise ValueError('Embedding artifact checksum mismatch; refuse inference')
    return root

def prepare():
    """Download exactly the reviewed model revision; TLS and LFS verification remain enabled."""
    from huggingface_hub import snapshot_download
    m=manifest();root=cache_root();root.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.environ.setdefault('HF_HOME',str(root/'.hf-home'))
    os.environ.setdefault('HF_XET_CACHE',str(root/'.hf-home'/'xet'))
    os.environ.setdefault('HF_HUB_DISABLE_TELEMETRY','1')
    path=snapshot_download(repo_id=m['repository'],revision=m['revision'],cache_dir=str(root),allow_patterns=list(m['files_sha256']))
    verify_model();return {'model':m['model'],'revision':m['revision'],'dimension':m['dimension'],'verified':True}

@lru_cache(maxsize=2)
def _model(root_str,version):
    root=verify_model()
    import onnxruntime
    onnxruntime.disable_telemetry_events()
    from fastembed import TextEmbedding
    return TextEmbedding(manifest()['model'],specific_model_path=str(root),cache_dir=root_str,threads=2,local_files_only=True)
@lru_cache(maxsize=2)
def _tokenizer(root_str):
    from tokenizers import Tokenizer
    tokenizer=Tokenizer.from_file(str(verify_model()/'tokenizer.json'));tokenizer.no_truncation();tokenizer.no_padding();return tokenizer

def split_text(text):
    if settings().embedding_model=='hash':
        return [text[i:i+1600] for i in range(0,len(text),1400)]
    offsets=_tokenizer(str(cache_root())).encode(text,add_special_tokens=False).offsets
    return [text[offsets[i][0]:offsets[min(i+223,len(offsets)-1)][1]] for i in range(0,len(offsets),192)]

def embed_many(texts):
    if not texts:return []
    if settings().embedding_model=='hash':
        vectors=[]
        for text in texts:
            v=np.zeros(128,dtype=np.float32)
            for token in re.findall(r'[a-z0-9_+-]+',text.lower()):
                b=hashlib.sha256(token.encode()).digest();v[int.from_bytes(b[:4])%128]+=1 if b[4]%2 else -1
            n=np.linalg.norm(v);vectors.append((v/n if n else v).tolist())
        return vectors
    model=_model(str(cache_root()),embedding_version())
    vectors=[v.astype(np.float32).tolist() for v in model.embed(texts,batch_size=32)]
    if any(len(v)!=dimension() or not np.isfinite(v).all() for v in vectors):raise ValueError('Invalid semantic embedding output')
    return vectors

def embed(text):return embed_many([text])[0]
