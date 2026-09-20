const fs=require('fs');
const sortJS=fs.readFileSync(process.argv[2],'utf8');

// sessionStorage compartido entre "cargas de pagina" (como en el navegador real)
const store={};
global.sessionStorage={getItem:k=>k in store?store[k]:null,
  setItem:(k,v)=>{store[k]=String(v);},removeItem:k=>{delete store[k];}};
global.location={pathname:'/cuarentena'};

function th(txt,nosort){return {txt,attrs:nosort?{'data-nosort':''}:{},lis:{},
  hasAttribute(k){return k in this.attrs;},setAttribute(k,v){this.attrs[k]=v;},
  getAttribute(k){return k in this.attrs?this.attrs[k]:null;},removeAttribute(k){delete this.attrs[k];},
  addEventListener(t,f){this.lis[t]=f;},click(){this.lis.click&&this.lis.click();}};}
function td(txt,sort){return {textContent:txt,
  getAttribute(k){return k==='data-sort'&&sort!==undefined?String(sort):null;}};}

// simula UNA carga de pagina con las filas dadas
function cargar(ips){
  const cab=[th('CPE'),th('Lista'),th('Motivo'),th('Por'),th('Enviado'),th('Ultima revision'),th('Accion',true)];
  const filas=ips.map(ip=>({cells:[td(ip),td('lista'),td('CnC'),td('ana'),td('01/01 00:00',1),td('—',0),td('')]}));
  const tbody={rows:filas,appendChild(r){const i=this.rows.indexOf(r);if(i>=0)this.rows.splice(i,1);this.rows.push(r);}};
  const tabla={tHead:{rows:[{cells:cab}]},tBodies:[tbody]};
  let lis=null;
  global.document={readyState:'loading',addEventListener(t,f){if(t==='DOMContentLoaded')lis=f;},
    querySelectorAll:s=>s==='table.orden'?[tabla]:[]};
  eval(sortJS);
  global.document.readyState='complete'; lis();
  return {cab,orden:()=>tbody.rows.map(r=>r.cells[0].textContent),aria:()=>cab.map(c=>c.getAttribute('aria-sort'))};
}

// --- 1a carga: el usuario ordena por CPE descendente ---
let p=cargar(['192.0.2.10','192.0.2.2','192.0.2.30']);
p.cab[0].click(); p.cab[0].click();
const esperado=p.orden().join();
if(esperado!=='192.0.2.30,192.0.2.10,192.0.2.2') throw new Error('orden inicial: '+esperado);
console.log('OK  el usuario ordena descendente:',esperado);

// --- pulsa Quitar: la pagina se recarga y una fila ya no esta ---
// el servidor manda el orden natural (ascendente): si el script NO hiciera nada,
// la tabla quedaria '192.0.2.2,192.0.2.30' y el usuario veria su orden perdido
p=cargar(['192.0.2.2','192.0.2.30']);
if(p.orden().join()!=='192.0.2.30,192.0.2.2')
  throw new Error('NO re-aplico el orden del usuario: '+p.orden().join());
console.log('OK  el servidor manda 192.0.2.2,192.0.2.30 y queda',p.orden().join(),'(descendente conservado)');
if(p.aria()[0]!=='descending') throw new Error('no restauro el indicador: '+p.aria());
console.log('OK  el indicador ▼ sigue en la columna CPE');

// --- el usuario cambia a ascendente: debe persistir el NUEVO sentido ---
p.cab[0].click();
p=cargar(['192.0.2.10','192.0.2.2','192.0.2.30']);
if(p.orden().join()!=='192.0.2.2,192.0.2.10,192.0.2.30') throw new Error('asc no persistio: '+p.orden());
console.log('OK  cambia a ascendente y tambien persiste:',p.orden().join());

// --- otra pagina no hereda el orden de esta ---
global.location={pathname:'/top'};
p=cargar(['192.0.2.10','192.0.2.2']);
if(p.aria()[0]!==null) throw new Error('otra pagina heredo el orden');
console.log('OK  el orden es por pagina (no se filtra a otras pestanas)');
console.log('\nTODO OK');
