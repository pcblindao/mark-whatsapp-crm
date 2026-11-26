import sys,tempfile,unittest,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'painel'))
from crm import CRM,Conflito
class TestConfig(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.crm=CRM(str(Path(self.tmp.name)/'crm.db'))
 def tearDown(self):self.tmp.cleanup()
 def config(self):return self.crm.listar()['config']
 def save(self,c):return self.crm.salvar({'acao':'configurar','config':c,'versao':c['versao']})
 def test_renomeia_coluna_preserva_registros_e_tipo(self):
  self.crm.salvar({'entidade':'oportunidades','titulo':'Venda','etapa':'Novo','valor_centavos':100})
  c=self.config();c['etapas'][0]['nome']='Entrada';c['etapas']=[c['etapas'][1],c['etapas'][0],*c['etapas'][2:]];self.save(c)
  d=self.crm.listar();self.assertEqual(d['oportunidades'][0]['etapa'],'Entrada');self.assertEqual(d['config']['etapas'][1]['tipo'],'aberta')
 def test_remove_coluna_ocupada_recusa_sem_mudar_config(self):
  self.crm.salvar({'entidade':'oportunidades','titulo':'Venda','etapa':'Novo'})
  c=self.config();c['empresa']['nome']='Não deve salvar';c['etapas']=c['etapas'][1:]
  with self.assertRaises(ValueError):self.save(c)
  self.assertEqual(self.config()['empresa']['nome'],'')
 def test_campos_obrigatorios_tipos_e_desativacao(self):
  c=self.config();f={'id':'segmento','nome':'Segmento','entidade':'clientes','tipo':'selecao','ativo':True,'obrigatorio':True,'opcoes':['Varejo','Serviços']};c['campos']=[f];self.save(c)
  with self.assertRaises(ValueError):self.crm.salvar({'entidade':'clientes','nome':'Teste'})
  with self.assertRaises(ValueError):self.crm.salvar({'entidade':'clientes','nome':'Teste','extras':{'segmento':'Outro'}})
  id=self.crm.salvar({'entidade':'clientes','nome':'Teste','extras':{'segmento':'Varejo'}})['id']
  c=self.config();c['campos'][0]['ativo']=False;self.save(c);self.crm.salvar({'entidade':'clientes','id':id,'nome':'Novo nome','extras':{}})
  self.assertEqual(self.crm.listar()['clientes'][0]['extras']['segmento'],'Varejo')
 def test_impede_reinterpretacao_e_opcao_em_uso(self):
  c=self.config();c['campos']=[dict(id='c1',nome='Número',entidade='clientes',tipo='numero',ativo=True,obrigatorio=False,opcoes=[])];self.save(c)
  c=self.config();c['campos'][0]['tipo']='texto'
  with self.assertRaises(ValueError):self.save(c)
 def test_concorrencia_config(self):
  c=self.config();self.save(c)
  with self.assertRaises(Conflito):self.save(c)
 def test_proposta_config_limites(self):
  c=self.config();c['propostas']['validade_dias']=0
  with self.assertRaises(ValueError):self.save(c)
if __name__=='__main__':unittest.main()
