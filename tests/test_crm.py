import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'painel'))
from crm import CRM
class TestCRM(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=str(Path(self.tmp.name)/'crm.db');self.crm=CRM(self.path)
 def tearDown(self): self.tmp.cleanup()
 def test_fluxo_e_persistencia(self):
  c=self.crm.salvar({'entidade':'clientes','nome':'Cliente de teste'})['id']
  o={'entidade':'oportunidades','titulo':'Proposta','cliente_id':c,'valor_centavos':12345,'etapa':'Novo'}
  o['id']=self.crm.salvar(o)['id'];o['etapa']='Ganho';self.crm.salvar(o)
  self.crm.salvar({'entidade':'tarefas','titulo':'Retornar','cliente_id':c,'prazo':'2026-12-01','concluida':0})
  d=CRM(self.path).listar();self.assertEqual(d['oportunidades'][0]['valor_centavos'],12345)
  self.assertEqual(d['oportunidades'][0]['etapa'],'Ganho');self.assertEqual(len(d['historico']),4)
 def test_recusa_cliente_inexistente(self):
  with self.assertRaises(ValueError): self.crm.salvar({'entidade':'oportunidades','titulo':'Teste','cliente_id':'inexistente','etapa':'Novo','valor_centavos':0})
  self.assertEqual(self.crm.listar()['oportunidades'],[])
 def test_validacao_valor_etapa_e_prazo(self):
  for delta in [{'valor_centavos':-1},{'valor_centavos':'abc'},{'etapa':'inventada'}]:
   with self.assertRaises(ValueError): self.crm.salvar(dict({'entidade':'oportunidades','titulo':'Teste','etapa':'Novo','valor_centavos':0},**delta))
  with self.assertRaises(ValueError): self.crm.salvar({'entidade':'tarefas','titulo':'Teste','prazo':'2026-99-99','concluida':0})
 def test_edicao_inexistente_nao_cria(self):
  with self.assertRaises(ValueError): self.crm.salvar({'entidade':'clientes','id':'nao-existe','nome':'Teste'})
 def test_tipo_nao_permite_sql(self):
  with self.assertRaises(ValueError): self.crm.salvar({'entidade':'clientes; DROP TABLE clientes','nome':'Teste'})
  self.assertEqual(self.crm.listar()['clientes'],[])
if __name__=='__main__':unittest.main()
