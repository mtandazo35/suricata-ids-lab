const fs=require('fs');
const js=fs.readFileSync(process.argv[2],'utf8');

// --- DOM minimo ---
function el(id,extra){return Object.assign({id,style:{},innerHTML:'',textContent:'',lis:{},
  classList:{cls:{},contains(c){return !!this.cls[c];},add(c){this.cls[c]=1;},remove(c){delete this.cls[c];}},
  addEventListener(t,f){this.lis[t]=f;},click(){this.lis.click&&this.lis.click();},
  appendChild(n){this.hijos=(this.hijos||[]).concat([n]);}},extra||{});}
function casilla(val){const c=el(null);c.value=val;c.checked=false;c.classList.cls.selm=1;return c;}

const casillas=[casilla('cuar|192.0.2.10'),casilla('dns|198.51.100.5'),casilla('cuar|192.0.2.11')];
const selall=el('selall'), bmasivo=el('bmasivo'), nmasivo=el('nmasivo');
const maslista=el('maslista'), mascampos=el('mascampos'), mmasivo=el('mmasivo');
const els={selall,bmasivo,nmasivo,maslista,mascampos,mmasivo,notif:null,fichamodal:el('fichamodal')};
const docLis={};
global.document={
  getElementById:id=>els[id]!==undefined?els[id]:null,
  querySelectorAll:s=>s==='input.selm'?casillas:[],
  addEventListener(t,f){docLis[t]=f;},
  createElement:t=>el(null,{tagName:t})
};
global.window={};
global.location={pathname:'/cuarentena'};
global.sessionStorage={getItem:()=>null,setItem(){},removeItem(){}};
eval(js);

let fallos=0;
const check=(d,c,e)=>{console.log((c?'  OK   ':' FALLA ')+d+(c?'':'  -> '+JSON.stringify(e)));if(!c)fallos++;};

check('al abrir, el boton esta deshabilitado', bmasivo.disabled===true, bmasivo.disabled);
check('el contador arranca en (0)', nmasivo.textContent==='(0)', nmasivo.textContent);

// marcar dos casillas
casillas[0].checked=true; docLis.change({target:casillas[0]});
casillas[2].checked=true; docLis.change({target:casillas[2]});
check('el contador refleja lo marcado', nmasivo.textContent==='(2)', nmasivo.textContent);
check('el boton se habilita', bmasivo.disabled===false, bmasivo.disabled);
check('"seleccionar todo" queda a medias (indeterminate)', selall.indeterminate===true, selall.indeterminate);

// seleccionar todo
selall.checked=true; docLis.change({target:selall});
check('"seleccionar todo" marca TODAS', casillas.every(c=>c.checked), casillas.map(c=>c.checked));
check('el contador pasa a (3)', nmasivo.textContent==='(3)', nmasivo.textContent);
check('ya no esta a medias', selall.indeterminate===false, selall.indeterminate);

// desmarcar todo
selall.checked=false; docLis.change({target:selall});
check('desmarca todas', casillas.every(c=>!c.checked), casillas.map(c=>c.checked));
check('el boton vuelve a deshabilitarse', bmasivo.disabled===true, bmasivo.disabled);

// abrir el modal con una de cada lista
casillas[0].checked=true; casillas[1].checked=true; docLis.change({target:casillas[0]});
bmasivo.click();
check('el modal flotante se muestra', mmasivo.style.display==='flex', mmasivo.style.display);
const textos=(maslista.hijos||[]).map(h=>(h.hijos||[]).map(x=>x.textContent).join(''));
check('lista las IPs elegidas', textos.length===2&&textos[0].indexOf('192.0.2.10')>=0, textos);
check('marca cual es de DNS', textos[1].indexOf('(DNS)')>0, textos);
const campos=(mascampos.hijos||[]).map(h=>({n:h.name,v:h.value,t:h.type}));
check('manda un campo oculto por IP, con su lista',
  campos.length===2&&campos.every(c=>c.t==='hidden'&&c.n==='sel')&&campos[0].v==='cuar|192.0.2.10', campos);

// cerrar con Escape
docLis.keydown({key:'Escape'});
check('Escape cierra el modal', mmasivo.style.display==='none', mmasivo.style.display);

// no abre si no hay nada marcado
casillas.forEach(c=>c.checked=false); docLis.change({target:casillas[0]});
bmasivo.click();
check('sin seleccion no abre el modal', mmasivo.style.display==='none', mmasivo.style.display);

console.log('\n'+(fallos?fallos+' fallo(s)':'TODO OK'));
process.exit(fallos?1:0);
