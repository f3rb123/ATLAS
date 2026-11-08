"""Container startup loads Docker secret selectors without exposing secret values."""
import os,sys
from pathlib import Path
if os.environ.get('ATLAS_DATABASE_URL_FILE_PASSWORD'):
 from urllib.parse import quote
 password=Path(os.environ['ATLAS_DATABASE_URL_FILE_PASSWORD']).read_text().strip()
 os.environ['ATLAS_DATABASE_URL']=os.environ['ATLAS_DATABASE_URL'].replace('{password}',quote(password,safe=''))
if os.environ.get('ATLAS_REDIS_PASSWORD_FILE'):
 from urllib.parse import quote
 password=Path(os.environ['ATLAS_REDIS_PASSWORD_FILE']).read_text().strip()
 os.environ['ATLAS_REDIS_URL']=os.environ['ATLAS_REDIS_URL'].replace('redis://','redis://:'+quote(password,safe='')+'@')
os.execvp(sys.argv[1],sys.argv[1:])
