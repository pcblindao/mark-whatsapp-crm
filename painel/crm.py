"""CRM do Mark WhatsApp CRM. Persistência transacional e integração autenticada."""
import json, os, sqlite3, uuid, re
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

ETAPAS=('Novo','Em atendimento','Proposta','Negociação','Ganho','Perdido')
CAMPOS={
 'clientes':('nome','telefone','email','empresa','jid','notas','origem','responsavel'),
 'oportunidades':('titulo','cliente_id','etapa','valor_centavos','responsavel','notas','previsao','motivo_perda'),
 'tarefas':('titulo','cliente_id','prazo','concluida','notas','responsavel','prioridade'),
 'produtos':('nome','descricao','valor_centavos'),
 'propostas':('titulo','cliente_id','status','validade','itens','desconto_centavos','notas'),
 'atividades':('titulo','cliente_id','tipo','notas'),
 'equipe':('nome','email','funcao'),
}
DEFAULTS={'etapa':'Novo','valor_centavos':0,'concluida':0,'prioridade':'Normal','status':'Rascunho','itens':[],'desconto_centavos':0,'tipo':'Nota'}
class Conflito(ValueError):pass
class CRM:
 def __init__(self,path):
  self.path=path
  with self.db() as c:
   c.execute('CREATE TABLE IF NOT EXISTS historico(id INTEGER PRIMARY KEY,entidade TEXT,registro_id TEXT,evento TEXT,em TEXT)')
   for t,campos in CAMPOS.items():
    c.execute('CREATE TABLE IF NOT EXISTS '+t+'(id TEXT PRIMARY KEY)')
    existentes={r[1] for r in c.execute('PRAGMA table_info('+t+')')}
    for k in (*campos,'atualizado','arquivado','criado'):
     if k not in existentes:
      tipo='INTEGER DEFAULT 0' if k in ('valor_centavos','concluida','desconto_centavos','arquivado') else "TEXT DEFAULT ''"
      c.execute('ALTER TABLE '+t+' ADD COLUMN '+k+' '+tipo)
   # Compatibilidade com a primeira versão.
   c.execute("UPDATE tarefas SET prioridade='Normal' WHERE prioridade='' OR prioridade IS NULL")
 @contextmanager
 def db(self):
  c=sqlite3.connect(self.path,timeout=15);c.row_factory=sqlite3.Row
  c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA journal_mode=WAL')
  try:
   with c:yield c
  finally:c.close()
 def listar(self):
  with self.db() as c:
   d={t:[dict(r) for r in c.execute('SELECT * FROM '+t+' ORDER BY atualizado DESC')] for t in CAMPOS}
   d['historico']=[dict(r) for r in c.execute('SELECT * FROM historico ORDER BY id DESC LIMIT 500')]
  for p in d['propostas']:
   p['itens']=json.loads(p['itens'] or '[]')
   p['total_centavos']=sum(i['quantidade']*i['valor_centavos'] for i in p['itens'])-p['desconto_centavos']
  return dict(d,etapas=ETAPAS,success=True)
 def salvar(self,d):
  t=d.get('entidade')
  if not isinstance(t,str) or t not in CAMPOS:raise ValueError('Tipo de registro inválido')
  acao=d.get('acao','salvar');ident=str(d.get('id') or uuid.uuid4());agora=datetime.now(timezone.utc).isoformat()
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE')
   antes=c.execute('SELECT * FROM '+t+' WHERE id=?',(ident,)).fetchone()
   if d.get('id') and not antes:raise ValueError('Registro não encontrado')
   if antes and d.get('versao') and d['versao']!=antes['atualizado']:raise Conflito('O registro foi alterado. Atualize a página antes de salvar.')
   if acao in ('arquivar','restaurar'):
    if not antes:raise ValueError('Registro não encontrado')
    c.execute('UPDATE '+t+' SET arquivado=?,atualizado=? WHERE id=?',(int(acao=='arquivar'),agora,ident))
    evento='Arquivado' if acao=='arquivar' else 'Restaurado'
   elif acao=='salvar':
    vals={k:d.get(k,antes[k] if antes else DEFAULTS.get(k,'')) for k in CAMPOS[t]}
    if antes and antes['arquivado']:raise ValueError('Restaure o registro antes de editar')
    for k,v in vals.items():
     if k in ('valor_centavos','concluida','desconto_centavos','itens'):continue
     if v is None and k=='cliente_id':continue
     if not isinstance(v,str) or len(v)>10000:raise ValueError('Campo inválido: '+k)
     vals[k]=v.strip()
    obrig='nome' if t in ('clientes','produtos','equipe') else 'titulo'
    if not vals[obrig] or len(vals[obrig])>200:raise ValueError('Informe '+obrig+' (até 200 caracteres)')
    if 'cliente_id' in vals:
     vals['cliente_id']=vals['cliente_id'] or None
     if vals['cliente_id'] and not c.execute('SELECT id FROM clientes WHERE id=? AND arquivado=0',(vals['cliente_id'],)).fetchone():raise ValueError('Selecione um cliente ativo')
    for k in ('prazo','previsao','validade'):
     if vals.get(k):
      try:datetime.strptime(vals[k],'%Y-%m-%d')
      except ValueError:raise ValueError('Data inválida: '+k)
    for k in ('valor_centavos','desconto_centavos'):
     if k in vals and (type(vals[k]) is not int or not 0<=vals[k]<=100000000000):raise ValueError('Valor inválido')
    if t=='clientes':
     if vals['jid'] and not re.fullmatch(r'[0-9]{5,25}@(s\.whatsapp\.net|lid|g\.us)',vals['jid']):raise ValueError('Conversa inválida')
     if vals['jid'] and c.execute('SELECT id FROM clientes WHERE jid=? AND id<>? AND arquivado=0',(vals['jid'],ident)).fetchone():raise ValueError('Essa conversa já está vinculada a um cliente')
    if t=='oportunidades' and vals['etapa'] not in ETAPAS:raise ValueError('Etapa inválida')
    if t=='tarefas':
     if vals['concluida'] not in (0,1):raise ValueError('Situação inválida')
     if vals['prioridade'] not in ('Baixa','Normal','Alta'):raise ValueError('Prioridade inválida')
    if t=='propostas':
     if vals['status'] not in ('Rascunho','Enviada','Aceita','Recusada'):raise ValueError('Situação inválida')
     itens=vals['itens'];itens=json.loads(itens) if isinstance(itens,str) else itens
     if not isinstance(itens,list) or not 1<=len(itens)<=100:raise ValueError('Inclua de 1 a 100 itens')
     limpos=[]
     for i in itens:
      if not isinstance(i,dict) or not isinstance(i.get('nome'),str) or not i['nome'].strip() or len(i['nome'])>200:raise ValueError('Descrição do item inválida')
      if type(i.get('quantidade')) is not int or not 1<=i['quantidade']<=10000:raise ValueError('Quantidade inválida')
      if type(i.get('valor_centavos')) is not int or not 0<=i['valor_centavos']<=100000000:raise ValueError('Preço inválido')
      limpos.append({k:i[k] for k in ('nome','quantidade','valor_centavos')})
     if vals['desconto_centavos']>sum(i['quantidade']*i['valor_centavos'] for i in limpos):raise ValueError('Desconto maior que o total')
     vals['itens']=json.dumps(limpos,ensure_ascii=False)
    if t=='atividades' and vals['tipo'] not in ('Nota','Ligação','Reunião','Retorno'):raise ValueError('Tipo inválido')
    cols=tuple(vals)+('atualizado',);args=tuple(vals.values())+(agora,)
    if antes:c.execute('UPDATE '+t+' SET '+','.join(k+'=?' for k in cols)+' WHERE id=?',args+(ident,))
    else:c.execute('INSERT INTO '+t+'(id,criado,'+','.join(cols)+') VALUES('+','.join('?' for _ in range(len(cols)+2))+')',(ident,agora)+args)
    evento=('Criado: ' if not antes else 'Atualizado: ')+vals[obrig]
    if antes and t=='oportunidades' and antes['etapa']!=vals['etapa']:evento=vals['titulo']+': '+antes['etapa']+' → '+vals['etapa']
   else:raise ValueError('Ação inválida')
   c.execute('INSERT INTO historico(entidade,registro_id,evento,em) VALUES(?,?,?,?)',(t,ident,evento,agora))
  return {'success':True,'id':ident}

def instalar_crm(Handler,g):
 crm=CRM(os.path.join(g['AQUI'],'crm.db'));anterior_get,anterior_post=Handler.do_GET,Handler.do_POST
 def get(self):
  p=urlparse(self.path).path
  if p not in ('/crm','/api/crm','/api/crm/contatos'):return anterior_get(self)
  if not self.portaria(False):return
  if p=='/api/crm':return self.json(crm.listar())
  if p=='/api/crm/contatos':
   try:
    d=g['api_chats']();chats=d if isinstance(d,list) else d.get('chats',[])
    return self.json({'success':True,'contatos':[{'jid':x['jid'],'nome':x.get('nome',''),'telefone':x.get('tel','')} for x in chats if x.get('tipo')=='individual']})
   except Exception:return self.json({'success':False,'erro':'Não foi possível carregar os contatos'},503)
  with open(os.path.join(g['AQUI'],'crm.html'),encoding='utf-8-sig') as f:html=f.read()
  self.enviar(200,html,'text/html; charset=utf-8',{'Content-Security-Policy':g['csp_com_scripts'](html)})
 def post(self):
  if urlparse(self.path).path!='/api/crm':return anterior_post(self)
  if not self.portaria(True):return
  try:
   n=int(self.headers.get('Content-Length','0'))
   if not 0<n<=100000:
    self.close_connection=True;return self.json({'success':False,'erro':'Corpo inválido'},400)
   d=json.loads(self.rfile.read(n))
   if not isinstance(d,dict):raise ValueError('Corpo inválido')
   return self.json(crm.salvar(d))
  except Conflito as e:return self.json({'success':False,'erro':str(e)},409)
  except (ValueError,TypeError) as e:return self.json({'success':False,'erro':str(e)},400)
  except sqlite3.Error:return self.json({'success':False,'erro':'Falha ao salvar o registro'},500)
 Handler.do_GET,Handler.do_POST=get,post
