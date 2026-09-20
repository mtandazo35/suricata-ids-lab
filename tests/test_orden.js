const fs=require('fs');
const js=fs.readFileSync(process.argv[2],'utf8');
global.location={pathname:'/cuarentena'};global.sessionStorage={getItem:()=>null,setItem(){},removeItem(){}};

// --- DOM minimo que respeta el orden REAL de carga ---
function th(txt,nosort){return {txt,attrs:nosort?{'data-nosort':''}:{},lis:{},
  hasAttribute(k){return k in this.attrs;},
  setAttribute(k,v){this.attrs[k]=v;},getAttribute(k){return k in this.attrs?this.attrs[k]:null;},
  removeAttribute(k){delete this.attrs[k];},
  addEventListener(t,f){this.lis[t]=f;},click(){this.lis.click&&this.lis.click();}};}
function td(txt,sort){return {textContent:txt,
  getAttribute(k){return k==='data-sort'&&sort!==undefined?String(sort):null;}};}
function tr(cells){return {cells};}

const cabeceras=[th('CPE'),th('Lista'),th('Motivo'),th('Por'),th('Enviado'),th('Ultima revision'),th('Accion',true)];
// 'Enviado' lleva data-sort con epoch: el texto dd/mm ordenaria mal entre meses
const filas=[
  tr([td('192.0.2.10'),td('infectados'),td('CnC'),td('ana'),   td('02/01 09:00',1735808400),td('—',0),td('')]),
  tr([td('192.0.2.2'), td('dns'),       td('DNS'),td('carlos'),td('30/12 22:00',1735603200),td('—',0),td('')]),
  tr([td('192.0.2.30'),td('infectados'),td('CnC'),td('beto'),  td('15/01 03:00',1736910000),td('—',0),td('')]),
];
const tbody={rows:filas,appendChild(r){const i=this.rows.indexOf(r);if(i>=0)this.rows.splice(i,1);this.rows.push(r);}};
const tabla={tHead:{rows:[{cells:cabeceras}]},tBodies:[tbody]};

let listener=null, consultado=false;
global.document={
  readyState:'loading',                       // el script corre ANTES de la tabla
  addEventListener(t,f){if(t==='DOMContentLoaded')listener=f;},
  querySelectorAll(sel){consultado=true;return sel==='table.orden'?[tabla]:[];}
};

eval(js);

// 1) al ejecutarse no debe haber tocado el DOM todavia
if(consultado) throw new Error('BUG: consulto las tablas antes de que existieran');
if(!listener)  throw new Error('BUG: no espero al DOM ni inicializo');
console.log('OK  no busca tablas al cargar; queda a la espera del DOM');

// 2) el navegador termina de leer la pagina
global.document.readyState='complete'; listener();
if(cabeceras[0].getAttribute('data-sort')!=='') throw new Error('no marco las cabeceras como ordenables');
if(cabeceras[6].getAttribute('data-sort')!==null) throw new Error('marco Accion, que no debe ordenar');
console.log('OK  cabeceras activadas (Accion excluida)');

const porIP=()=>tbody.rows.map(r=>r.cells[0].textContent);
const porFecha=()=>tbody.rows.map(r=>r.cells[4].textContent);

// 3) ascendente / descendente por CPE (orden natural: .2 antes que .10)
cabeceras[0].click();
if(porIP().join()!=='192.0.2.2,192.0.2.10,192.0.2.30') throw new Error('asc CPE: '+porIP());
console.log('OK  ascendente por CPE:',porIP().join(' '));
cabeceras[0].click();
if(porIP().join()!=='192.0.2.30,192.0.2.10,192.0.2.2') throw new Error('desc CPE: '+porIP());
console.log('OK  descendente por CPE:',porIP().join(' '));
if(cabeceras[0].getAttribute('aria-sort')!=='descending') throw new Error('sin indicador de sentido');

// 4) por 'Por' (texto)
cabeceras[3].click();
if(tbody.rows.map(r=>r.cells[3].textContent).join()!=='ana,beto,carlos') throw new Error('asc Por');
console.log('OK  ascendente por "Por": ana beto carlos');
if(cabeceras[0].getAttribute('aria-sort')!==null) throw new Error('quedo el indicador en otra columna');
console.log('OK  el indicador se mueve de columna');

// 5) por fecha: debe usar el epoch, no el texto (30/12 es ANTERIOR a 02/01)
cabeceras[4].click();
if(porFecha().join()!=='30/12 22:00,02/01 09:00,15/01 03:00') throw new Error('fechas mal: '+porFecha());
console.log('OK  fechas por tiempo real (30/12 antes que 02/01), no por texto');
console.log('\nTODO OK');
