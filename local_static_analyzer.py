#!/usr/bin/env python3
"""Local Static Malware Analyzer v3.0 - Ultra Compressed"""
import os,sys,re,json,struct,hashlib,logging,argparse,subprocess
from pathlib import Path;from datetime import datetime;from math import log2;from typing import Dict,Any,List
try:from dotenv import load_dotenv;load_dotenv()
except:pass
try:import pefile
except:pefile=None
try:import yara
except:yara=None
try:import ssdeep
except:ssdeep=None
try:import magic
except:magic=None
try:import requests
except:requests=None
logging.basicConfig(level=logging.INFO,format='%(asctime)s-%(levelname)s-%(message)s');L=logging.getLogger(__name__)

class S:
    ST={'.text','.data','.rdata','.bss','.rsrc','.reloc','.idata','.edata','.pdata','.tls','CODE','DATA'}
    SYS={'cmd.exe','powershell.exe','rundll32.exe','regsvr32.exe','mshta.exe','cscript.exe','wscript.exe','netstat.exe','ipconfig.exe','ping.exe','tracert.exe','nslookup.exe','cipher.exe','attrib.exe','schtasks.exe','tasklist.exe','taskkill.exe','net.exe','net1.exe','sc.exe','reg.exe','whoami.exe','systeminfo.exe'}
    CRY={'cipher.exe','certutil.exe','certreq.exe','dpapi.exe'}
    def __init__(s,p,c=None):s.p=Path(p);s.c=c or{};s.r={"ts":datetime.now().isoformat(),"path":str(s.p)}
    def run(s)->Dict:
        L.info(f"Analyzing:{s.p}");s.meta();s.hash();s.hex(256);s.ent()
        if s.ispe():s.pe();s.rich();s.pdb();s.tls();s.over();s.ver();s.imp();s.caps();s.catim();s.ep();s.auth()
        s.strs();s.pack();s.anti();s.lang();s.inst();s.role();s.cfg();s.antidbg();s.yara()
        s.admin();s.systool();s.clust();s.benign();s.malind();s.contra();s.vt();s.score();s.susp()
        L.info(f"Done:{s.r.get('risk_score',{}).get('verdict','?')}");return s.r
    def ispe(s):
        try:
            with open(s.p,'rb')as f:return f.read(2)==b'MZ'
        except:return False
    def meta(s):
        try:
            st=s.p.stat();s.r["metadata"]={"name":s.p.name,"size":st.st_size,"mime":magic.from_file(str(s.p),mime=True)if magic else"?"}
        except Exception as e:L.error(f"Meta:{e}")
    def hash(s):
        try:
            with open(s.p,'rb')as f:d=f.read()
            s.r["hashes"]={"md5":hashlib.md5(d).hexdigest(),"sha1":hashlib.sha1(d).hexdigest(),"sha256":hashlib.sha256(d).hexdigest(),"ssdeep":ssdeep.hash(d)if ssdeep else"N/A"}
        except Exception as e:L.error(f"Hash:{e}")
    def pe(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p));sec=[{"n":x.Name.decode('utf-8','ignore').strip('\x00'),"e":round(x.get_entropy(),2)}for x in pe.sections]
            s.r["pe_analysis"]={"is_pe":True,"is_dll":pe.FILE_HEADER.Characteristics&0x2000!=0,"is_64":pe.FILE_HEADER.Machine==0x8664,"imphash":pe.get_imphash(),"sections":sec,"ep":hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)};pe.close()
        except Exception as e:L.error(f"PE:{e}")
    def imp(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p));im={};t=0
            if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
                for e in pe.DIRECTORY_ENTRY_IMPORT:
                    d=e.dll.decode('utf-8','ignore');fn=[{"n":i.name.decode('utf-8','ignore')if i.name else f"ord_{i.ordinal}"}for i in e.imports]
                    im[d]=fn;t+=len(fn)
            ex=[];
            if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):ex=[{"n":e.name.decode('utf-8','ignore')if e.name else f"ord_{e.ordinal}"}for e in pe.DIRECTORY_ENTRY_EXPORT.symbols[:30]]
            s.r["imports_exports"]={"imports":im,"total_imports":t,"exports":ex};pe.close()
        except Exception as e:L.error(f"Imp:{e}")
    def strs(s,ml=4):
        try:
            with open(s.p,'rb')as f:d=f.read()
            ar=re.compile(rb'[\x20-\x7e]{%d,}'%ml);ur=re.compile(rb'(?:[\x20-\x7e]\x00){%d,}'%ml)
            st=[x.decode('ascii','ignore')for x in ar.findall(d)]+[x.decode('utf-16le','ignore')for x in ur.findall(d)]
            s.r["strings"]=s.catstr(list(set(st)))
        except Exception as e:L.error(f"Str:{e}")
    def catstr(s,st):
        c={"urls":[],"ips":[],"paths":[],"regs":[],"btc":[],"sus":[],"cnt":len(st)}
        ur,ir=re.compile(r'https?://[^\s<>"]+'),re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        pr,rr=re.compile(r'[A-Za-z]:\\[^\s<>"]+'),re.compile(r'(HKEY_|HKLM|HKCU|SOFTWARE\\)')
        br=re.compile(r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b')
        kw=['password','keylog','ransom','encrypt','decrypt','backdoor','inject','trojan','bitcoin','.onion']
        for x in st:
            if ur.search(x):c["urls"].append(x[:80])
            elif ir.search(x):c["ips"].append(x)
            elif pr.search(x):c["paths"].append(x[:80])
            elif rr.search(x):c["regs"].append(x[:80])
            elif br.search(x):c["btc"].append(x)
            elif any(k in x.lower()for k in kw):c["sus"].append(x[:80])
        return c
    def pack(s):
        if not yara:s.r["packer_detection"]={"packed":False};return
        try:
            ru=yara.compile(source='rule U{strings:$u="UPX!"condition:$u}rule A{strings:$a=".aspack"condition:$a}')
            m=ru.match(str(s.p));h=[]
            if s.ispe()and pefile:
                pe=pefile.PE(str(s.p))
                for x in pe.sections:
                    if pe.OPTIONAL_HEADER.AddressOfEntryPoint>=x.VirtualAddress and pe.OPTIONAL_HEADER.AddressOfEntryPoint<x.VirtualAddress+x.Misc_VirtualSize:
                        if x.get_entropy()>7.0:h.append("High entropy EP")
                if hasattr(pe,'DIRECTORY_ENTRY_IMPORT')and sum(1 for _ in pe.DIRECTORY_ENTRY_IMPORT)<3:h.append("Low imports")
                pe.close()
            s.r["packer_detection"]={"packers":[x.rule for x in m],"hints":h,"packed":len(m)>0 or len(h)>0}
        except Exception as e:L.error(f"Pack:{e}")
    def hex(s,n=256):
        try:
            with open(s.p,'rb')as f:d=f.read(n)
            s.r["hex_dump"]=''.join(f'{b:02x}'for b in d[:32])
        except:pass
    def ent(s):
        try:
            with open(s.p,'rb')as f:d=f.read()
            e=s._ent(d);s.r["entropy"]={"val":round(e,2),"class":"Packed"if e>7.2 else"Normal"if e<6 else"Compressed"}
        except:pass
    def _ent(s,d):
        if not d:return 0.0
        fr={};
        for b in d:fr[b]=fr.get(b,0)+1
        return-sum((c/len(d))*log2(c/len(d))for c in fr.values()if c>0)
    def anti(s):
        try:
            with open(s.p,'rb')as f:c=f.read()
            t=[]
            for p in[b'IsDebuggerPresent',b'CheckRemoteDebuggerPresent',b'NtQueryInformationProcess']:
                if p in c:t.append(f"AntiDbg:{p.decode()}")
            for p in[b'VMware',b'VirtualBox',b'QEMU']:
                if p in c:t.append(f"AntiVM:{p.decode()}")
            s.r["anti_analysis"]={"techs":list(set(t)),"cnt":len(set(t))}
        except:pass
    def lang(s):
        try:
            with open(s.p,'rb')as f:c=f.read()
            l=[];
            if b'mscoree.dll'in c:l.append(".NET")
            if b'MSVCRT'in c:l.append("C/C++")
            if b'python'in c.lower():l.append("Py")
            s.r["language"]={"langs":l or["?"]}
        except:pass
    def rich(s):
        if not pefile:return
        try:pe=pefile.PE(str(s.p));s.r["rich_header"]={"present":hasattr(pe,'RICH_HEADER')and pe.RICH_HEADER is not None};pe.close()
        except:s.r["rich_header"]={"present":False}
    def pdb(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p));info={"path":None}
            if hasattr(pe,'DIRECTORY_ENTRY_DEBUG'):
                for d in pe.DIRECTORY_ENTRY_DEBUG:
                    if d.struct.Type==2:
                        data=pe.get_data(d.struct.PointerToRawData,d.struct.SizeOfData)
                        if data[:4]==b'RSDS':info["path"]=data[24:].split(b'\x00')[0].decode('utf-8','ignore')
            pe.close();s.r["pdb_info"]=info
        except:s.r["pdb_info"]={"path":None}
    def tls(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p));info={"has":hasattr(pe,'DIRECTORY_ENTRY_TLS'),"cbs":[]}
            if info["has"]:
                t=pe.DIRECTORY_ENTRY_TLS;cr=t.struct.AddressOfCallBacks-pe.OPTIONAL_HEADER.ImageBase
                for _ in range(10):
                    sz=8 if pe.OPTIONAL_HEADER.Magic!=0x10b else 4
                    addr=struct.unpack('<Q'if sz==8 else'<I',pe.get_data(cr,sz))[0]
                    if addr==0:break
                    info["cbs"].append(hex(addr));cr+=sz
            pe.close();s.r["tls_callbacks"]=info
        except:s.r["tls_callbacks"]={"has":False,"cbs":[]}
    def over(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p));fs=os.path.getsize(s.p);info={"has":False,"size":0}
            off=pe.get_overlay_data_start_offset()
            if off and off<fs:
                sz=fs-off
                if sz>0:
                    info={"has":True,"offset":off,"size":sz,"ratio":round((sz/fs)*100,1)}
                    with open(s.p,'rb')as f:f.seek(off);d=f.read(min(sz,65536))
                    info["ent"]=round(s._ent(d),2)
                    if d[:4]==b'MSCF':info["inst_payload"]=True
            pe.close();s.r["overlay"]=info
        except:s.r["overlay"]={"has":False}
    def ver(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p));info={"has":False,"company":None,"product":None,"orig":None}
            if hasattr(pe,'FileInfo'):
                for fi in pe.FileInfo:
                    for i in fi:
                        if hasattr(i,'StringTable'):
                            for st in i.StringTable:
                                for k,v in st.entries.items():
                                    ky,vl=k.decode('utf-8','ignore'),v.decode('utf-8','ignore')
                                    info["has"]=True
                                    if ky=='CompanyName':info["company"]=vl
                                    elif ky=='ProductName':info["product"]=vl
                                    elif ky=='OriginalFilename':info["orig"]=vl
            pe.close();s.r["version_info"]=info
        except:s.r["version_info"]={"has":False}
    def caps(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p))
            beh={"keylog":(["GetAsyncKeyState","SetWindowsHookEx"],2),"inject":(["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread"],2),"cred":(["CredEnumerate","CryptUnprotectData"],1),"net":(["InternetOpen","HttpOpenRequest","URLDownloadToFile"],2)}
            cp={"detected":[],"details":{}}
            if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
                ai=set()
                for e in pe.DIRECTORY_ENTRY_IMPORT:
                    for i in e.imports:
                        if i.name:ai.add(i.name.decode('utf-8','ignore'))
                for b,(apis,rq)in beh.items():
                    mt=[a for a in apis if a in ai]
                    if len(mt)>=rq:cp["detected"].append(b);cp["details"][b]=mt
            pe.close();s.r["capability_mapping"]=cp
        except:s.r["capability_mapping"]={"detected":[]}
    def catim(s):s.r["import_categories"]={}
    def ep(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p));er=pe.OPTIONAL_HEADER.AddressOfEntryPoint;info={"rva":hex(er),"sec":None,"sus":[]}
            for x in pe.sections:
                if x.VirtualAddress<=er<x.VirtualAddress+x.Misc_VirtualSize:info["sec"]=x.Name.decode('utf-8','ignore').strip('\x00');break
            pe.close();s.r["entry_point_analysis"]=info
        except:s.r["entry_point_analysis"]={}
    def yara(s):
        if not yara:s.r["yara_matches"]={"matches":[]};return
        try:
            ru=yara.compile(source='rule Sus{strings:$a="cmd.exe"$b="powershell"$c="mimikatz"condition:2 of them}rule Ran{strings:$a="encrypt"$b="bitcoin"$c="ransom"condition:2 of them}')
            m=ru.match(str(s.p));s.r["yara_matches"]={"matches":[{"rule":x.rule}for x in m],"families":[x.rule for x in m if'ran'in x.rule.lower()]}
        except:s.r["yara_matches"]={"matches":[]}
    def auth(s):
        if not pefile:return
        try:
            pe=pefile.PE(str(s.p));sec=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            info={"signed":sec.VirtualAddress!=0 and sec.Size!=0,"signer":None}
            if info["signed"]:
                try:
                    r=subprocess.run(['osslsigncode','verify',str(s.p)],capture_output=True,text=True,timeout=30)
                    for ln in r.stdout.split('\n'):
                        if'Subject:'in ln:info["signer"]=ln.split('Subject:')[1].strip();break
                except:pass
            pe.close();s.r["authenticode"]=info
        except:s.r["authenticode"]={"signed":False}
    def inst(s):
        try:
            with open(s.p,'rb')as f:d=f.read()
            info={"is":False,"fw":None,"conf":0.0};st=str(s.r.get("strings",{})).lower()
            if b'\xef\xbe\xad\xde'in d or'nullsoft'in st or'nsis'in st:info={"is":True,"fw":"NSIS","conf":0.9}
            elif'inno setup'in st:info={"is":True,"fw":"Inno","conf":0.85}
            elif d[:8]==b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':info={"is":True,"fw":"MSI","conf":0.95}
            elif s.r.get("overlay",{}).get("inst_payload"):info={"is":True,"fw":"Generic","conf":0.7}
            s.r["installer_info"]=info
        except:s.r["installer_info"]={"is":False}
    def role(s):
        try:
            info={"role":"unknown","conf":"low"}
            if s.r.get("installer_info",{}).get("is"):info={"role":"installer","conf":"high"}
            elif s.r.get("pe_analysis",{}).get("is_dll"):info={"role":"library","conf":"high"}
            elif s.r.get("version_info",{}).get("has"):info={"role":"application","conf":"medium"}
            s.r["file_role"]=info
        except:s.r["file_role"]={"role":"unknown"}
    def cfg(s):s.r["config_detection"]={}
    def antidbg(s):
        try:
            with open(s.p,'rb')as f:d=f.read()
            info={"rdtsc":d.count(b'\x0F\x31'),"cpuid":d.count(b'\x0F\xA2'),"techs":[]}
            if info["rdtsc"]>2:info["techs"].append("RDTSC")
            if info["cpuid"]>0:info["techs"].append("CPUID")
            s.r["instruction_anti_debug"]=info
        except:s.r["instruction_anti_debug"]={}
    def admin(s):
        sg=[];pd=(s.r.get("pdb_info",{}).get("path")or"").lower()
        if any(p in pd for p in["sysinternals","procmon"]):sg.append("sysinternals")
        vi=s.r.get("version_info",{})
        if any(v in str(vi.get("company","")).lower()for v in["sysinternals","microsoft"]):sg.append("vendor")
        if s.r.get("authenticode",{}).get("signed"):sg.append("signed")
        ia=len(sg)>=2;s.r["admin_tool_detection"]={"is":ia,"signals":sg};return ia
    def systool(s):
        fn=s.p.name.lower();vi=s.r.get("version_info",{});au=s.r.get("authenticode",{})
        is_sys=fn in s.SYS
        if not is_sys and(vi.get("orig")or"").lower()in s.SYS:is_sys=True
        if is_sys and au.get("signer")and"microsoft"in au.get("signer","").lower():is_sys=True
        s.r["system_tool_detection"]={"is":is_sys,"fn":fn};return is_sys
    def clust(s):
        try:
            CL={"inject":{"apis":{"OpenProcess","VirtualAllocEx","WriteProcessMemory"},"wt":35},"hollow":{"apis":{"CreateProcess","NtUnmapViewOfSection","WriteProcessMemory"},"wt":45}}
            im=s.r.get("imports_exports",{}).get("imports",{});aa=set()
            for fn in im.values():
                for f in fn:aa.add(f.get("n","")if isinstance(f,dict)else str(f))
            mt=[]
            for n,c in CL.items():
                rq=c["apis"]&aa
                if len(rq)>=len(c["apis"])*0.6:mt.append({"cl":n,"wt":c["wt"],"apis":list(rq)})
            s.r["api_clusters"]={"detected":mt,"wt":sum(m["wt"]for m in mt)}
        except:s.r["api_clusters"]={}
    def benign(s):
        try:
            sc,ev=0,[]
            if s.r.get("authenticode",{}).get("signed"):sc+=20;ev.append("Signed")
            if s.r.get("installer_info",{}).get("is"):sc+=25;ev.append("Installer")
            if s.r.get("version_info",{}).get("has"):sc+=5;ev.append("VerInfo")
            sec=s.r.get("pe_analysis",{}).get("sections",[])
            std=sum(1 for x in sec if x.get("n","")in s.ST)
            if sec and std>=len(sec)*0.8:sc+=3;ev.append("StdSec")
            s.r["benign_indicators"]={"score":sc,"ev":ev}
        except:s.r["benign_indicators"]={"score":0}
    def malind(s):
        try:
            sc,ind=0,[];st=s.r.get("strings",{})
            if st.get("sus"):sc+=min(len(st["sus"])*3,30);ind.append("SusStr")
            if st.get("btc"):sc+=20;ind.append("BTC")
            for u in st.get("urls",[]):
                if any(t in u.lower()for t in['.onion','.bit']):sc+=15;ind.append("SusURL")
            if not s.r.get("authenticode",{}).get("signed")and not s.r.get("version_info",{}).get("has"):
                if not s.r.get("installer_info",{}).get("is"):sc+=20;ind.append("NoSign+NoVer")
            cp=s.r.get("capability_mapping",{}).get("detected",[])
            for c,p in[("inject",35),("cred",40),("keylog",30)]:
                if c in cp:sc+=p;ind.append(f"Cap:{c}")
            an=s.r.get("anti_analysis",{}).get("techs",[])
            if len(an)>=3:sc+=15;ind.append("AntiAnal")
            ym=s.r.get("yara_matches",{})
            if ym.get("matches"):sc+=25;ind.append("YARA")
            s.r["malware_indicators"]={"score":sc,"ind":ind}
        except:s.r["malware_indicators"]={"score":0}
    def contra(s):
        try:
            ct=[];rl=s.r.get("file_role",{}).get("role","unknown");au=s.r.get("authenticode",{});vi=s.r.get("version_info",{});cl=s.r.get("api_clusters",{}).get("detected",[])
            if rl=="installer"and not vi.get("has")and not au.get("signed"):ct.append({"type":"inst_no_id","wt":30,"desc":"Installer no ID"})
            co=str(vi.get("company","")).lower();tv=au.get("signed")and any(v in co for v in['microsoft','google','adobe','mozilla','apple','valve'])
            if rl in["application","installer"]and cl and not s.r.get("admin_tool_detection",{}).get("is")and not tv:
                ij=[c for c in cl if c["cl"]in["inject","hollow"]]
                if ij:ct.append({"type":"app_inject","wt":40,"desc":f"{rl} with injection"})
            if any(tc in co for tc in['microsoft','google','adobe'])and not au.get("signed"):
                is_sys=s.r.get("system_tool_detection",{}).get("is",False);wt=15 if is_sys else 35
                ct.append({"type":"fake_vendor","wt":wt,"desc":f"Claims {co} but unsigned"+(" (systool)"if is_sys else"")})
            s.r["contradictions"]={"detected":ct,"cnt":len(ct),"wt":sum(c["wt"]for c in ct)}
        except:s.r["contradictions"]={"detected":[]}
    def vt(s):
        try:
            h=s.r.get("hashes",{}).get("sha256");ti={"vt":{"status":"?","det":False,"pos":0,"tot":0,"names":[],"link":None,"threat":None},"iocs":{}}
            vk=os.environ.get("VT_API_KEY","")or s.c.get("tools",{}).get("virustotal_api_key","")
            if vk and h and requests:
                try:
                    L.info(f"VT:{h[:16]}...");rp=requests.get(f"https://www.virustotal.com/api/v3/files/{h}",headers={"x-apikey":vk},timeout=30)
                    if rp.status_code==200:
                        d=rp.json();at=d.get("data",{}).get("attributes",{});st=at.get("last_analysis_stats",{});ps=st.get("malicious",0)+st.get("suspicious",0);tt=sum(st.values())
                        nm=[r.get("result")for e,r in at.get("last_analysis_results",{}).items()if r.get("category")=="malicious"and r.get("result")][:10]
                        ti["vt"]={"status":"found","det":ps>0,"pos":ps,"tot":tt,"names":nm,"link":f"https://www.virustotal.com/gui/file/{h}","threat":at.get("popular_threat_classification",{}).get("suggested_threat_label")}
                        L.info(f"VT:{ps}/{tt}")
                    elif rp.status_code==404:ti["vt"]["status"]="not_found"
                    elif rp.status_code==401:ti["vt"]["status"]="auth_err"
                    elif rp.status_code==429:ti["vt"]["status"]="rate_limit"
                except Exception as e:ti["vt"]["status"]=f"err:{e}"
            elif not vk:ti["vt"]["status"]="no_key"
            st=s.r.get("strings",{});ti["iocs"]={"c2":st.get("urls",[])[:10],"ips":st.get("ips",[])[:10],"btc":st.get("btc",[])}
            s.r["threat_intel"]=ti
        except:s.r["threat_intel"]={}
    def score(s):
        try:
            rl=s.r.get("file_role",{}).get("role","unknown");ii=rl=="installer";ia=s.r.get("admin_tool_detection",{}).get("is",False);isy=s.r.get("system_tool_detection",{}).get("is",False)
            au=s.r.get("authenticode",{});vi=s.r.get("version_info",{});sig=au.get("signed",False);hv=vi.get("has",False);fs=s.r.get("metadata",{}).get("size",0);ti=s.r.get("imports_exports",{}).get("total_imports",0);ipe=s.r.get("pe_analysis",{}).get("is_pe",False)
            rs={"score":0,"verdict":"?","contra":[],"ind":[],"base":[],"trust":[],"model":"v3.1"}
            #Phase0:Base
            bl=0
            if not sig and not hv:
                if rl=="unknown":bl+=25;rs["base"].append("NoSig+NoVer:+25")
                elif not ii:bl+=15;rs["base"].append("NoSig+NoVer:+15")
            if ipe and fs<50000 and ti<15:bl+=15;rs["base"].append(f"Small({fs}B)+FewImp({ti}):+15")
            en=s.r.get("entropy",{}).get("val",0)
            if en>7.2:bl+=10;rs["base"].append(f"HighEnt({en}):+10")
            if s.r.get("packer_detection",{}).get("packed")and not ii:bl+=10;rs["base"].append("Packed:+10")
            tot=bl
            #Phase0.5:Patterns
            im=s.r.get("imports_exports",{}).get("imports",{});aa=set()
            for fn in im.values():
                for f in fn:aa.add(f.get("n","")if isinstance(f,dict)else str(f))
            cr={"CryptEncrypt","CryptDecrypt","CryptGenKey","CryptAcquireContext","CryptAcquireContextW","BCryptEncrypt","BCryptDecrypt"}
            fe={"FindFirstFile","FindFirstFileW","FindNextFile","FindNextFileW"};fm={"WriteFile","WriteFileEx","MoveFile","DeleteFile"}
            ld={"CreateProcess","CreateProcessW","WinExec","ShellExecute","CreateRemoteThread","VirtualAllocEx","WriteProcessMemory"}
            dl={"URLDownloadToFile","URLDownloadToFileW","InternetReadFile"};sl={"SetWindowsHookEx","BlockInput","ShowWindow","LockWorkStation"}
            ps={"RegSetValueEx","RegSetValueExW","CreateService","CreateServiceW"}
            hc,he,hm,hl,hd,hs,hp=[bool(aa&x)for x in[cr,fe,fm,ld,dl,sl,ps]]
            fn=s.p.name.lower()
            if hc and he and fn not in s.CRY:lsc=30+(15 if hm else 0)+(10 if not sig and rl=="unknown"else 0);tot+=lsc;rs["ind"].append(f"LOCKER:+{lsc}")
            if hs and rl=="unknown"and not sig:ssc=25+(15 if hp else 0);tot+=ssc;rs["ind"].append(f"SCREENLOCK:+{ssc}")
            if fs<100000 and rl=="unknown":
                if hl and hd:tot+=35;rs["ind"].append("LOADER:+35")
                elif hd and not sig:tot+=25;rs["ind"].append("DROPPER:+25")
                elif"VirtualAllocEx"in aa and"WriteProcessMemory"in aa:tot+=40;rs["ind"].append("INJECT:+40")
                elif"VirtualAllocEx"in aa and not sig:tot+=20;rs["ind"].append("SUSALLOC:+20")
            if ipe and fs<50000 and not sig and rl=="unknown":
                sc=sum([hc,he,hm,hl,hd,hs,hp])
                if sc>=2:tot+=20;rs["ind"].append(f"MINIMAL({sc}):+20")
            #Phase1:Contra
            ct=s.r.get("contradictions",{}).get("detected",[]);hct=len(ct)>0
            for c in ct:
                wt=c["wt"]
                if isy and c.get("type")=="fake_vendor":wt=min(wt,15);rs["contra"].append(f"{c['desc']}:+{wt}(systool)")
                else:rs["contra"].append(f"{c['desc']}:+{wt}")
                tot+=wt
            #Phase2:Clust
            cw=s.r.get("api_clusters",{}).get("wt",0)
            if hct and not ia:tot+=cw
            #Phase3:YARA
            ym=s.r.get("yara_matches",{})
            if ym.get("matches"):ys=25+(len(ym["matches"])-1)*10+len(ym.get("families",[]))*20
            else:ys=0
            if hct and ys:tot+=ys;rs["ind"].append(f"YARA:+{ys}")
            #Phase4:VT
            vt=s.r.get("threat_intel",{}).get("vt",{});vp=vt.get("pos",0);vtot=vt.get("tot",1)or 1;vdr=vp/vtot;vtr=False
            if vt.get("det")and vp>10:
                vb=min(int(vp*0.7),50)if vp>30 else min(vp,30);tot+=vb;rs["ind"].append(f"VT{vp}/{vtot}:+{vb}")
                if vdr>0.5 and sig:vtr=True;rs["trust"].append("VT>50%:TrustRevoked")
            #Phase5:Trust
            if not hct and not vtr:
                if sig:
                    sn=str(au.get("signer","")).lower()
                    for v,rd in[("microsoft",-40),("google",-40),("adobe",-30),("valve",-25)]:
                        if v in sn:tot=max(0,tot+rd);rs["trust"].append(f"SignedBy{v}:{rd}");break
                    else:tot=max(0,tot-15);rs["trust"].append("Signed:-15")
                if ii and s.r.get("installer_info",{}).get("conf",0)>0.7:tot=max(0,tot-30);rs["trust"].append("Installer:-30")
            elif hct:rs["trust"].append("TrustDisabled(contra)")
            #Phase5.5:SysTool
            if isy and not hct:rd=min(tot,45);tot=max(0,tot-rd);rs["trust"].append(f"SysTool:-{rd}")
            tot=min(tot,100);rs["score"]=tot
            #Phase6:Verdict
            if tot>=70:rs["verdict"]="Malicious"if hct else"High Risk"
            elif tot>=50:rs["verdict"]="High Risk"if hct else"Suspicious"
            elif tot>=30:rs["verdict"]="Medium Risk"
            elif tot>=15:rs["verdict"]="Low Risk"
            elif tot>0:rs["verdict"]="Minimal"if ii or ia else"Unrated"
            else:rs["verdict"]="Clean"if ii or ia or isy else"Unrated"
            s.r["risk_score"]=rs;L.info(f"SCORE:{tot}-{rs['verdict']}(c:{len(ct)},i:{len(rs['ind'])})")
        except Exception as e:s.r["risk_score"]={"score":0,"verdict":"Err","e":str(e)}
    def susp(s):
        try:
            rp={"apis":[],"notes":[]};sc=s.r.get("risk_score",{}).get("score",0)
            if sc>=50:rp["notes"].append(f"HIGH:{sc}")
            elif sc>=30:rp["notes"].append(f"MED:{sc}")
            s.r["why_suspicious"]=rp
        except:s.r["why_suspicious"]={}
    def human_size(s,sz):
        for u in['B','KB','MB','GB']:
            if sz<1024:return f"{sz:.1f}{u}";sz/=1024
        return f"{sz:.1f}TB"

def main():
    p=argparse.ArgumentParser(description='Local Static Malware Analyzer v3.1');p.add_argument('sample');p.add_argument('-o','--output');p.add_argument('--config',default='config.json');p.add_argument('--stdout',action='store_true')
    a=p.parse_args()
    if not os.path.exists(a.sample):print(f"Err:NotFound:{a.sample}",file=sys.stderr);sys.exit(1)
    c={}
    if os.path.exists(a.config):
        try:
            with open(a.config,'r')as f:c=json.load(f)
        except:pass
    an=S(a.sample,c);r=an.run()
    if a.stdout:print(json.dumps(r,indent=2))
    else:
        o=a.output or f"{r.get('hashes',{}).get('sha256','out')}.json"
        with open(o,'w')as f:json.dump(r,f,indent=2);print(f"Saved JSON:{o}")
        
        # Auto-parse to text
        try:
            ps=os.path.join(os.path.dirname(os.path.abspath(__file__)),'parser.py')
            to=o.replace('.json','.txt')
            subprocess.run(['python3',ps,o,'-o',to],check=True)
            print(f"Saved Text Report:{to}")
        except Exception as e:
            print(f"Err Parsing:{e}")

    rs=r.get("risk_score",{});vt=r.get("threat_intel",{}).get("vt",{})
    print(f"\n{'='*50}\nVERDICT:{rs.get('verdict','?')}(Score:{rs.get('score',0)}/100)")
    if vt.get("det"):print(f"VT:{vt.get('pos',0)}/{vt.get('tot',0)}-{vt.get('threat','')}")
    print('='*50)

if __name__=="__main__":main()
