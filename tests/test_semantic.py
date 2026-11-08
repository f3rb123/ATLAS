"""Actual model integration test; unit tests explicitly use the labelled lexical fallback."""
import pytest,numpy as np
from atlas.embeddings import verify_model,embed,split_text,manifest
from atlas.config import settings
@pytest.mark.semantic
def test_verified_neural_model_and_token_preserving_chunks(monkeypatch):
 monkeypatch.setenv('ATLAS_EMBEDDING_MODEL','sentence-transformers/all-MiniLM-L6-v2')
 monkeypatch.setenv('ATLAS_EMBEDDING_CACHE_DIR','/workspace/ATLAS/.runtime/models');settings.cache_clear()
 verify_model()
 a=np.array(embed('Tenant authorization protects private user records'))
 b=np.array(embed('Object access checks enforce tenant isolation'))
 c=np.array(embed('A recipe for baking chocolate cake'))
 assert len(a)==384 and np.isfinite(a).all()
 assert np.dot(a,b)>np.dot(a,c)
 from tokenizers import Tokenizer
 tok=Tokenizer.from_file(str(verify_model()/'tokenizer.json'));tok.no_truncation();tok.no_padding()
 text=('Tenant access boundary and secure object authorization. '*500)
 chunks=split_text(text);assert len(chunks)>2
 assert all(len(tok.encode(t,add_special_tokens=False).ids)<=224 for t in chunks)
 settings.cache_clear()
