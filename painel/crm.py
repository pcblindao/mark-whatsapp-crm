"""CRM do Mark WhatsApp CRM. Persistência transacional e integração autenticada."""
import json, os, sqlite3, uuid, re, math, copy
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
CONFIG_PADRAO={'empresa':{'nome':'','documento':'','email':'','telefone':'','endereco':''},'propostas':{'validade_dias':15,'condicoes':''},'etapas':[{'id':'etapa_'+str(i),'nome':n,'tipo':'ganho' if n=='Ganho' else 'perdido' if n=='Perdido' else 'aberta','cor':'#008069'} for i,n in enumerate(ETAPAS)],'campos':[],'versao':0}
DEFAULTS={'etapa':'Novo','valor_centavos':0,'concluida':0,'prioridade':'Normal','status':'Rascunho','itens':[],'desconto_centavos':0,'tipo':'Nota'}
class Conflito(ValueError):pass
class CRM:
 def __init__(self,path):
  self.path=path
  with self.db() as c:
   c.execute('CREATE TABLE IF NOT EXISTS historico(id INTEGER PRIMARY KEY,entidade TEXT,registro_id TEXT,evento TEXT,em TEXT)')
   c.execute('CREATE TABLE IF NOT EXISTS configuracao(id INTEGER PRIMARY KEY CHECK(id=1),dados TEXT NOT NULL)')
   for t,campos in CAMPOS.items():
    c.execute('CREATE TABLE IF NOT EXISTS '+t+'(id TEXT PRIMARY KEY)')
    existentes={r[1] for r in c.execute('PRAGMA table_info('+t+')')}
    for k in (*campos,'atualizado','arquivado','criado','extras'):
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
   cfg=self.config(c)
   d['historico']=[dict(r) for r in c.execute('SELECT * FROM historico ORDER BY id DESC LIMIT 500')]
  for t in CAMPOS:
   for item in d[t]:item['extras']=json.loads(item.get('extras') or '{}')
  for p in d['propostas']:
   p['itens']=json.loads(p['itens'] or '[]')
   p['total_centavos']=sum(i['quantidade']*i['valor_centavos'] for i in p['itens'])-p['desconto_centavos']
  return dict(d,etapas=[x['nome'] for x in cfg['etapas']],config=cfg,success=True)
 def salvar(self,d):
  if d.get('acao')=='configurar':return self.configurar(d)
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
    cfg=self.config(c)
    vals={k:d.get(k,antes[k] if antes else DEFAULTS.get(k,'')) for k in CAMPOS[t]}
    if t=='oportunidades' and not antes and 'etapa' not in d:vals['etapa']=next(x['nome'] for x in cfg['etapas'] if x['tipo']=='aberta')
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
    if t=='oportunidades' and vals['etapa'] not in [x['nome'] for x in cfg['etapas']]:raise ValueError('Etapa inválida')
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
    vals['extras']=json.dumps(self.validar_extras(t,d.get('extras'),antes,cfg),ensure_ascii=False)
    cols=tuple(vals)+('atualizado',);args=tuple(vals.values())+(agora,)
    if antes:c.execute('UPDATE '+t+' SET '+','.join(k+'=?' for k in cols)+' WHERE id=?',args+(ident,))
    else:c.execute('INSERT INTO '+t+'(id,criado,'+','.join(cols)+') VALUES('+','.join('?' for _ in range(len(cols)+2))+')',(ident,agora)+args)
    evento=('Criado: ' if not antes else 'Atualizado: ')+vals[obrig]
    if antes and t=='oportunidades' and antes['etapa']!=vals['etapa']:evento=vals['titulo']+': '+antes['etapa']+' → '+vals['etapa']
   else:raise ValueError('Ação inválida')
   c.execute('INSERT INTO historico(entidade,registro_id,evento,em) VALUES(?,?,?,?)',(t,ident,evento,agora))
  return {'success':True,'id':ident}

 def config(self,c):
  row=c.execute('SELECT dados FROM configuracao WHERE id=1').fetchone()
  return json.loads(row[0]) if row else copy.deepcopy(CONFIG_PADRAO)
 def configurar(self,d):
  novo=d.get('config')
  if not isinstance(novo,dict):raise ValueError('Configuração inválida')
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE');old=self.config(c)
   if d.get('versao')!=old['versao']:raise Conflito('As configurações mudaram. Atualize antes de salvar.')
   etapas=novo.get('etapas');campos=novo.get('campos')
   if not isinstance(etapas,list) or not 3<=len(etapas)<=20:raise ValueError('Use de 3 a 20 colunas')
   ids=set();nomes=set();clean=[]
   for e in etapas:
    if not isinstance(e,dict):raise ValueError('Coluna inválida')
    id=e.get('id');nome=e.get('nome','').strip();tipo=e.get('tipo');cor=e.get('cor','#008069')
    if not isinstance(id,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',id) or id in ids:raise ValueError('Identificador de coluna inválido')
    if not nome or len(nome)>60 or nome.casefold() in nomes:raise ValueError('Os nomes das colunas devem ser únicos')
    if tipo not in ('aberta','ganho','perdido') or not re.fullmatch(r'#[0-9a-fA-F]{6}',cor):raise ValueError('Tipo ou cor de coluna inválidos')
    ids.add(id);nomes.add(nome.casefold());clean.append(dict(id=id,nome=nome,tipo=tipo,cor=cor))
   if sum(e['tipo']=='ganho' for e in clean)!=1 or sum(e['tipo']=='perdido' for e in clean)!=1 or not any(e['tipo']=='aberta' for e in clean):raise ValueError('Mantenha uma coluna ganha, uma perdida e pelo menos uma aberta')
   byid={e['id']:e for e in clean};renames={}
   for e in old['etapas']:
    if e['id'] not in byid:
     if c.execute('SELECT 1 FROM oportunidades WHERE etapa=? LIMIT 1',(e['nome'],)).fetchone():raise ValueError('Mova as oportunidades da coluna '+e['nome']+' antes de removê-la (incluindo arquivadas)')
    elif e['nome']!=byid[e['id']]['nome']:renames[e['nome']]=byid[e['id']]['nome']
   if not isinstance(campos,list) or len(campos)>100:raise ValueError('Limite de 100 campos')
   fields=[];seen=set();oldfields={f['id']:f for f in old['campos']}
   for f in campos:
    if not isinstance(f,dict):raise ValueError('Campo inválido')
    id=f.get('id');label=f.get('nome','').strip();entity=f.get('entidade');tipo=f.get('tipo')
    if not isinstance(id,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',id) or id in seen:raise ValueError('Identificador de campo inválido')
    if entity not in CAMPOS or not label or len(label)>80 or tipo not in ('texto','numero','data','selecao','booleano'):raise ValueError('Definição de campo inválida')
    if id in oldfields and (oldfields[id]['tipo']!=tipo or oldfields[id]['entidade']!=entity):raise ValueError('Crie outro campo para mudar o tipo ou módulo; os dados existentes serão preservados')
    opts=f.get('opcoes',[])
    if not isinstance(opts,list) or len(opts)>50 or any(not isinstance(x,str) or not x.strip() or len(x)>100 for x in opts):raise ValueError('Opções inválidas')
    opts=list(dict.fromkeys(x.strip() for x in opts))
    if tipo=='selecao' and not opts:raise ValueError('Informe as opções da lista')
    if type(f.get('ativo',True)) is not bool or type(f.get('obrigatorio',False)) is not bool:raise ValueError('Estado de campo inválido')
    if id in oldfields and tipo=='selecao' and set(oldfields[id]['opcoes'])-set(opts):
     removed=set(oldfields[id]['opcoes'])-set(opts)
     for row in c.execute('SELECT extras FROM '+entity):
      if json.loads(row[0] or '{}').get(id) in removed:raise ValueError('Uma opção removida ainda está em uso')
    seen.add(id);fields.append(dict(id=id,nome=label,entidade=entity,tipo=tipo,opcoes=opts,ativo=f.get('ativo',True),obrigatorio=f.get('obrigatorio',False)))
   # Campos removidos ficam inativos para preservar valores e permitir reativação.
   fields.extend(dict(f,ativo=False) for f in old['campos'] if f['id'] not in seen)
   empresa=novo.get('empresa',{});proposal=novo.get('propostas',{})
   if not isinstance(empresa,dict) or not isinstance(proposal,dict):raise ValueError('Dados da empresa inválidos')
   company={}
   for k in CONFIG_PADRAO['empresa']:
    v=empresa.get(k,'')
    if not isinstance(v,str) or len(v)>500:raise ValueError('Dados da empresa longos demais')
    company[k]=v.strip()
   days=proposal.get('validade_dias',15);terms=proposal.get('condicoes','')
   if type(days) is not int or not 1<=days<=365 or not isinstance(terms,str) or len(terms)>10000:raise ValueError('Padrões de proposta inválidos')
   cfg=dict(empresa=company,propostas=dict(validade_dias=days,condicoes=terms),etapas=clean,campos=fields,versao=old['versao']+1)
   if renames:
    cases=' '.join('WHEN ? THEN ?' for _ in renames);args=[v for pair in renames.items() for v in pair]
    c.execute('UPDATE oportunidades SET etapa=CASE etapa '+cases+' ELSE etapa END',args)
   c.execute('INSERT INTO configuracao(id,dados) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET dados=excluded.dados',(json.dumps(cfg,ensure_ascii=False),))
   c.execute('INSERT INTO historico(entidade,registro_id,evento,em) VALUES(?,?,?,?)',('configuracao','1','Configurações atualizadas',datetime.now(timezone.utc).isoformat()))
  return {'success':True,'config':cfg}
 def validar_extras(self,t,novos,antes,cfg):
  result=json.loads(antes['extras'] or '{}') if antes else {}
  if novos is not None:
   if not isinstance(novos,dict):raise ValueError('Campos personalizados inválidos')
   allowed={f['id'] for f in cfg['campos'] if f['entidade']==t and f['ativo']}
   if any(k not in allowed for k in novos):raise ValueError('Campo personalizado indisponível; atualize a tela')
   result.update(novos)
  for f in cfg['campos']:
   if f['entidade']!=t or not f['ativo']:continue
   v=result.get(f['id'])
   if v is None or v=='':
    if f['obrigatorio']:raise ValueError('Preencha o campo '+f['nome'])
    continue
   tipo=f['tipo']
   if tipo in ('texto','data','selecao') and (not isinstance(v,str) or len(v)>5000):raise ValueError('Valor inválido: '+f['nome'])
   if tipo=='numero' and (type(v) not in (int,float) or not math.isfinite(v)):raise ValueError('Número inválido: '+f['nome'])
   if tipo=='booleano' and type(v) is not bool:raise ValueError('Seleção inválida: '+f['nome'])
   if tipo=='selecao' and v not in f['opcoes']:raise ValueError('Opção inválida: '+f['nome'])
   if tipo=='data':
    try:datetime.strptime(v,'%Y-%m-%d')
    except ValueError:raise ValueError('Data inválida: '+f['nome'])
  return result

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
