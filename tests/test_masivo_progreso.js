const fs=require('fs');
const js=fs.readFileSync(process.argv[2],'utf8');

function el(id,extra){return Object.assign({id,style:{},innerHTML:'',textContent:'',lis:{},disabled:false,
  classList:{cls:{},contains(c){return !!this.cls[c];},add(c){this.cls[c]=1;},remove(c){delete this.cls[c];}},
  addEventListener(t,f){this.lis[t]=f;},click(){this.lis.click&&this.lis.click();},
  appendChild(n){this.hijos=(this.hijos||[]).concat([n]);n.padre=this;}},extra||{});}
function casilla(val){const c=el(null);c.value=val;c.checked=false;c.classList.cls.selm=1;
  const td=el(null),tr=el(null);td.padre=tr;c.parentNode=td;td.parentNode=tr;return c;}

const casillas=[casilla('cuar|10.6.1.89'),casilla('cuar|10.6.2.82'),casilla('dns|10.6.0.144')];
const els={selall:el('selall'),bmasivo:el('bmasivo'),nmasivo:el('nmasivo'),maslista:el('maslista'),
  mascampos:el('mascampos'),mmasivo:el('mmasivo'),fichamodal:el('fichamodal'),notif:null,
  massub:el('massub'),masprog:el('masprog'),masbar:el('masbar'),massi:el('massi'),masno:el('masno'),
  fmasivo:el('fmasivo')};
const docLis={};
global.document={getElementById:id=>els[id]!==undefined?els[id]:null,
  querySelectorAll:s=>s==='input.selm'?casillas:[],
  querySelector:s=>{const m=/value="(.+)"/.exec(s);return m?casillas.find(c=>c.value===m[1])||null:null;},
  addEventListener(t,f){docLis[t]=f;},createElement:t=>el(null,{tagName:t})};

// fetch simulado: la 2a IP falla (el router no responde)
const pedidos=[]; let bloqueadoDurante=null;
global.fetch=(url,opts)=>{pedidos.push({url,body:opts.body});if(bloqueadoDurante===null)bloqueadoDurante=window.masRun===true;
  const ip=decodeURIComponent(opts.body.split('=')[1]).split('|')[1];
  const falla = ip==='10.6.2.82';
  return Promise.resolve({json:()=>Promise.resolve(
    falla?{ok:false,ip,err:'router no responde'}:{ok:true,ip,err:''})});};
let destino=null;
global.location={pathname:'/cuarentena',set href(v){destino=v;},get href(){return destino;}};
global.window={fetch:global.fetch};
const realTimeout=setTimeout; global.setTimeout=(f)=>realTimeout(f,0);
const guardado={};
global.sessionStorage={getItem:k=>guardado[k]||null,setItem:(k,v)=>{guardado[k]=String(v);},removeItem:k=>{delete guardado[k];}};
eval(js);

let fallos=0;
const check=(d,c,e)=>{console.log((c?'  OK   ':' FALLA ')+d+(c?'':'  -> '+JSON.stringify(e)));if(!c)fallos++;};

// marcar las tres y abrir
casillas.forEach(c=>c.checked=true); docLis.change({target:casillas[0]});
els.bmasivo.click();
check('el modal lista las 3', (els.maslista.hijos||[]).length===3, (els.maslista.hijos||[]).length);

// lanzar el proceso y dejar que resuelvan las promesas
els.fmasivo.lis.submit({preventDefault(){}});
(async()=>{
for(let k=0;k<200;k++) await new Promise(r=>realTimeout(r,0));

check('hace UNA peticion por IP', pedidos.length===3, pedidos.length);
check('cada una va a /cuarentena/quitar-uno', pedidos.every(p=>p.url==='/cuarentena/quitar-uno'), pedidos[0]);
check('manda la lista de origen (cuar/dns)',
  pedidos[2].body.indexOf('dns%7C')>0, pedidos[2].body);
const estados=(els.maslista.hijos||[]).map(li=>li.hijos[0].textContent);
check('marca OK las que salieron', estados[0]==='\u2713'&&estados[2]==='\u2713', estados);
check('marca la que fallo', estados[1]==='\u2715', estados);
check('NO se detiene en el fallo (procesa las 3)', pedidos.length===3, pedidos.length);
const liFallo=els.maslista.hijos[1];
check('muestra el motivo del fallo',
  (liFallo.hijos||[]).some(h=>h.textContent==='router no responde'), liFallo.hijos.map(h=>h.textContent));
check('la barra llega al 100%', els.masbar.style.width==='100%', els.masbar.style.width);
check('resume 2 quitadas y 1 con error',
  /2<\/b> quitada/.test(els.massub.innerHTML)&&/1<\/b> con error/.test(els.massub.innerHTML), els.massub.innerHTML);
check('recarga con el resumen en el mensaje',
  destino&&destino.indexOf('2%20entrada')>0&&destino.indexOf('1%20con%20error')>0, destino);
check('desmarca las casillas que si salieron',
  casillas[0].checked===false&&casillas[1].checked===true, casillas.map(c=>c.checked));
check('bloquea el cierre MIENTRAS corre', bloqueadoDurante===true, bloqueadoDurante);
check('y vuelve a permitir cerrarlo al terminar', window.masRun===false, window.masRun);
check('deja marcada la posicion para no saltar arriba',
  guardado['posact:/cuarentena']==='1', guardado);

console.log('\n'+(fallos?fallos+' fallo(s)':'TODO OK'));
process.exit(fallos?1:0);
})();
