"""CRM persistente, isolado das mensagens e da sessÃ£o WhatsApp."""
import json, os, sqlite3, uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

ETAPAS = ('Novo', 'Em atendimento', 'Proposta', 'NegociaÃ§Ã£o', 'Ganho', 'Perdido')
CAMPOS = {
 'clientes': ('nome','telefone','email','empresa','jid','notas'),
 'oportunidades': ('titulo','cliente_id','etapa','valor_centavos','responsavel','notas'),
 'tarefas': ('titulo','cliente_id','prazo','concluida','notas'),
}
class CRM:
 def __init__(self, path):
  self.path = path
  with self.db() as c:
   c.executescript('''
   CREATE TABLE IF NOT EXISTS clientes(id TEXT PRIMARY KEY,nome TEXT NOT NULL,telefone TEXT,email TEXT,empresa TEXT,jid TEXT,notas TEXT,atualizado TEXT);
   CREATE TABLE IF NOT EXISTS oportunidades(id TEXT PRIMARY KEY,titulo TEXT NOT NULL,cliente_id TEXT REFERENCES clientes(id),etapa TEXT,valor_centavos INTEGER,responsavel TEXT,notas TEXT,atualizado TEXT);
   CREATE TABLE IF NOT EXISTS tarefas(id TEXT PRIMARY KEY,titulo TEXT NOT NULL,cliente_id TEXT REFERENCES clientes(id),prazo TEXT,concluida INTEGER,notas TEXT,atualizado TEXT);
   CREATE TABLE IF NOT EXISTS historico(id INTEGER PRIMARY KEY,entidade TEXT,registro_id TEXT,evento TEXT,em TEXT);
   ''')
 @contextmanager
 def db(self):
  c=sqlite3.connect(self.path,timeout=10); c.row_factory=sqlite3.Row
  c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA journal_mode=WAL')
  try:
   with c: yield c
  finally: c.close()
 def listar(self):
  with self.db() as c:
   d={t:[dict(r) for r in c.execute('SELECT * FROM '+t+' ORDER BY atualizado DESC')] for t in CAMPOS}
   d['historico']=[dict(r) for r in c.execute('SELECT * FROM historico ORDER BY id DESC LIMIT 100')]
  return dict(d,etapas=ETAPAS,success=True)
 def salvar(self,d):
  t=d.get('entidade'); campos=CAMPOS.get(t)
  if not campos: raise ValueError('Tipo de registro invÃ¡lido')
  ident=str(d.get('id') or uuid.uuid4()); vals={k:d.get(k,'') for k in campos}
  obrig='nome' if t=='clientes' else 'titulo'
  for k,v in vals.items():
   if k not in ('valor_centavos','concluida'):
    if not isinstance(v,str) or len(v)>5000: raise ValueError('Campo invÃ¡lido: '+k)
    vals[k]=v.strip()
  if not vals[obrig] or len(vals[obrig])>200: raise ValueError('Informe '+obrig+' (atÃ© 200 caracteres)')
  if 'cliente_id' in vals: vals['cliente_id']=vals['cliente_id'] or None
  if t=='oportunidades':
   if vals['etapa'] not in ETAPAS: raise ValueError('Etapa invÃ¡lida')
   v=vals['valor_centavos']
   if isinstance(v,bool) or not isinstance(v,int) or not 0<=v<=100000000000: raise ValueError('Valor invÃ¡lido')
  if t=='tarefas':
   if vals['concluida'] not in (0,1,False,True): raise ValueError('SituaÃ§Ã£o invÃ¡lida')
   if vals['prazo']:
    try: datetime.strptime(vals['prazo'],'%Y-%m-%d')
    except ValueError: raise ValueError('Prazo invÃ¡lido')
  agora=datetime.now(timezone.utc).isoformat()
  with self.db() as c:
   antes=c.execute('SELECT * FROM '+t+' WHERE id=?',(ident,)).fetchone()
   if d.get('id') and not antes: raise ValueError('Registro nÃ£o encontrado')
   if vals.get('cliente_id') and not c.execute('SELECT id FROM clientes WHERE id=?',(vals['cliente_id'],)).fetchone(): raise ValueError('Cliente nÃ£o encontrado')
   cols=tuple(vals)+('atualizado',); args=tuple(vals.values())+(agora,)
   if antes:
    c.execute('UPDATE '+t+' SET '+','.join(k+'=?' for k in cols)+' WHERE id=?',args+(ident,))
   else:
    c.execute('INSERT INTO '+t+' (id,'+','.join(cols)+') VALUES ('+','.join('?' for _ in range(len(cols)+1))+')',(ident,)+args)
   evento='Criado' if not antes else 'Atualizado'
   if antes and t=='oportunidades' and antes['etapa']!=vals['etapa']: evento=antes['etapa']+' â†’ '+vals['etapa']
   c.execute('INSERT INTO historico(entidade,registro_id,evento,em) VALUES(?,?,?,?)',(t,ident,evento,agora))
  return {'success':True,'id':ident}

def instalar_crm(Handler,g):
 crm=CRM(os.path.join(g['AQUI'],'crm.db'))
 anterior_get,anterior_post=Handler.do_GET,Handler.do_POST
 def get(self):
  p=urlparse(self.path).path
  if p not in ('/crm','/api/crm'): return anterior_get(self)
  if not self.portaria(False): return
  if p=='/api/crm': return self.json(crm.listar())
  with open(os.path.join(g['AQUI'],'crm.html'),encoding='utf-8') as f: html=f.read()
  self.enviar(200,html,'text/html; charset=utf-8', {'Content-Security-Policy': g['csp_com_scripts'](html)})
 def post(self):
  if urlparse(self.path).path!='/api/crm': return anterior_post(self)
  if not self.portaria(True): return
  try:
   n=int(self.headers.get('Content-Length','0'))
   if not 0<n<=40000:
    self.close_connection=True; return self.json({'success':False,'erro':'Corpo invÃ¡lido'},400)
   d=json.loads(self.rfile.read(n))
   if not isinstance(d,dict): raise ValueError('Corpo invÃ¡lido')
   return self.json(crm.salvar(d))
  except (ValueError,TypeError): return self.json({'success':False,'erro':'Verifique os campos do registro'},400)
  except sqlite3.Error: return self.json({'success':False,'erro':'Falha ao salvar o registro'},500)
 Handler.do_GET,Handler.do_POST=get,post
