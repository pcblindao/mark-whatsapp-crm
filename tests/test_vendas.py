import sys,tempfile,unittest,sqlite3
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'painel'))
from crm import CRM,Conflito
class TestVendas(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=str(Path(self.tmp.name)/'crm.db');self.crm=CRM(self.path)
 def tearDown(self):self.tmp.cleanup()
 def test_proposta_total_e_rejeicao_desconto(self):
  p={'entidade':'propostas','titulo':'Proposta teste','status':'Rascunho','itens':[{'nome':'Serviço','quantidade':2,'valor_centavos':15000}],'desconto_centavos':1000}
  self.crm.salvar(p);self.assertEqual(self.crm.listar()['propostas'][0]['total_centavos'],29000)
  p['desconto_centavos']=30001
  with self.assertRaises(ValueError):self.crm.salvar(p)
  self.assertEqual(len(self.crm.listar()['propostas']),1)
 def test_atualizacao_parcial_e_conflito(self):
  id=self.crm.salvar({'entidade':'oportunidades','titulo':'Venda','etapa':'Novo','valor_centavos':500})['id'];o=self.crm.listar()['oportunidades'][0]
  self.crm.salvar({'entidade':'oportunidades','id':id,'etapa':'Ganho','versao':o['atualizado']})
  with self.assertRaises(Conflito):self.crm.salvar({'entidade':'oportunidades','id':id,'etapa':'Perdido','versao':o['atualizado']})
  atual=self.crm.listar()['oportunidades'][0];self.assertEqual(atual['titulo'],'Venda');self.assertEqual(atual['valor_centavos'],500)
 def test_arquivar_restaurar_preserva_vinculos(self):
  c=self.crm.salvar({'entidade':'clientes','nome':'Teste'})['id']
  self.crm.salvar({'entidade':'tarefas','titulo':'Retornar','cliente_id':c})
  self.crm.salvar({'entidade':'clientes','id':c,'acao':'arquivar'})
  self.assertEqual(self.crm.listar()['tarefas'][0]['cliente_id'],c)
  self.crm.salvar({'entidade':'clientes','id':c,'acao':'restaurar'})
  self.assertEqual(self.crm.listar()['clientes'][0]['arquivado'],0)
 def test_conversa_duplicada(self):
  d={'entidade':'clientes','nome':'Teste','jid':'5500000000000@s.whatsapp.net'};self.crm.salvar(d)
  with self.assertRaises(ValueError):self.crm.salvar(d)
 def test_migracao_preserva_cliente_antigo(self):
  path=str(Path(self.tmp.name)/'legacy.db');c=sqlite3.connect(path)
  c.execute('CREATE TABLE clientes(id TEXT PRIMARY KEY,nome TEXT NOT NULL,telefone TEXT,email TEXT,empresa TEXT,jid TEXT,notas TEXT,atualizado TEXT)')
  c.execute("INSERT INTO clientes(id,nome) VALUES('antigo','Cliente antigo')");c.commit();c.close()
  novo=CRM(path);d=novo.listar()['clientes'][0];self.assertEqual(d['nome'],'Cliente antigo');self.assertEqual(d['arquivado'],0)
if __name__=='__main__':unittest.main()
