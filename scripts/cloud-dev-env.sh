#!/usr/bin/env bash
# Isolated cloud development state only. Never points at the original VPS/data.
export UV_CACHE_DIR=/workspace/.cache/uv
export XDG_CACHE_HOME=/workspace/.cache
export ATLAS_ENV=development
export ATLAS_DATABASE_URL=sqlite:///.runtime/cloud-dev/atlas.db
export ATLAS_DATA_DIR=.runtime/cloud-dev
export ATLAS_MASTER_KEY_FILE=.runtime/cloud-dev/master.key
export ATLAS_EXTERNAL_URL=http://localhost:3000
export ATLAS_EMBEDDING_CACHE_DIR=/workspace/ATLAS/.runtime/models
# Leave the real semantic model as the product default. Corpus/weights may be absent.
# Hash embeddings are used only by the explicitly labelled isolated test fixtures.
