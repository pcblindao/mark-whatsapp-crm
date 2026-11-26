import os, shutil
from pathlib import Path
os.umask(0o077)
p=Path('/data/WhatsApp-Assistente/painel'); p.mkdir(parents=True,exist_ok=True)
for f in Path('/app/painel').iterdir():
 if f.is_file(): shutil.copyfile(f,p/f.name)
os.chdir(p)
os.execvp('supervisord',['supervisord','-c','/app/deploy/supervisord.conf'])
