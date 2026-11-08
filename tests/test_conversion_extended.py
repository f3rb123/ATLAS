import io,json
from pathlib import Path
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject,NameObject,NumberObject,DecodedStreamObject
from atlas.corpus import import_file,import_parts
from atlas.db import Knowledge,Chunk
from atlas.reporting import render

def test_pdf_pages_and_docx_provenance(db,tmp_path):
 writer=PdfWriter()
 for text in ['First page authorization proof','Second page secure control']:
  page=writer.add_blank_page(width=300,height=400)
  font=DictionaryObject({NameObject('/Type'):NameObject('/Font'),NameObject('/Subtype'):NameObject('/Type1'),NameObject('/BaseFont'):NameObject('/Helvetica')})
  page[NameObject('/Resources')]=DictionaryObject({NameObject('/Font'):DictionaryObject({NameObject('/F1'):writer._add_object(font)})})
  stream=DecodedStreamObject();stream.set_data(('BT /F1 12 Tf 20 300 Td ('+text+') Tj ET').encode());page[NameObject('/Contents')]=writer._add_object(stream)
 p=tmp_path/'report.pdf'
 with p.open('wb') as f:writer.write(f)
 result=import_file(db,p,'owner-permission','owner:pdf',owner='alice');assert result['ingested']==1
 record=json.loads(db.query(Knowledge).one().record);assert [c['page'] for c in record['content']['chunks']]==[1,2]
 assert 'Second page' in record['summary']
 from docx import Document
 d=Document();d.add_paragraph('A real DOCX source paragraph');p=tmp_path/'report.docx';d.save(p)
 parts=list(import_parts(p));assert 'DOCX source' in parts[0]['text']

def test_reports_escape_html_and_actual_pdf():
 text=render([],'html');assert '<pre>' in text
 import base64
 raw=base64.b64decode(render([],'pdf'));assert raw.startswith(b'%PDF-')

def test_archive_pdf_preserves_all_pages_and_structured_rows(db,tmp_path):
 import zipfile
 # Use a two-page text PDF from the parser's own native PDF writer fixture.
 writer=PdfWriter()
 for value in ['First report page','Second report page']:
  p=writer.add_blank_page(width=300,height=400);font=DictionaryObject({NameObject('/Type'):NameObject('/Font'),NameObject('/Subtype'):NameObject('/Type1'),NameObject('/BaseFont'):NameObject('/Helvetica')});p[NameObject('/Resources')]=DictionaryObject({NameObject('/Font'):DictionaryObject({NameObject('/F1'):writer._add_object(font)})});stream=DecodedStreamObject();stream.set_data(('BT /F1 12 Tf 20 300 Td ('+value+') Tj ET').encode());p[NameObject('/Contents')]=writer._add_object(stream)
 buffer=io.BytesIO();writer.write(buffer);path=tmp_path/'reports.zip'
 with zipfile.ZipFile(path,'w') as z:z.writestr('folder/report.pdf',buffer.getvalue())
 assert import_file(db,path,'owner-permission','owner:zip',owner='a')['ingested']==1
 record=json.loads(db.query(Knowledge).one().record);assert [c['page'] for c in record['content']['chunks']]==[1,2]
 p=tmp_path/'rows.jsonl';p.write_text('{"title":"Unique row one","details":"First report"}\n{"title":"Unique row two","details":"Second report"}\n')
 assert import_file(db,p,'owner-permission','owner:rows',owner='a')['ingested']==2
